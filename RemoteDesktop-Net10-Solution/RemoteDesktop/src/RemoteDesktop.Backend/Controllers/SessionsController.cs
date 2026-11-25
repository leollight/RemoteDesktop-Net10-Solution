using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Sessions;
using RemoteDesktop.Infrastructure.Persistence;
using RemoteDesktop.Media;
using RemoteDesktop.Security;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api/sessions")]
public sealed class SessionsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly ISessionAuthorisationService _sessionAuth;
    private readonly ISessionParticipantAuthorizer _participantAuthorizer;
    private readonly IEffectiveRelayService _relayService;
    private readonly ControlPlaneNotifier _notifier;

    public SessionsController(
        ApplicationDbContext db,
        ISessionAuthorisationService sessionAuth,
        ISessionParticipantAuthorizer participantAuthorizer,
        IEffectiveRelayService relayService,
        ControlPlaneNotifier notifier)
    {
        _db = db;
        _sessionAuth = sessionAuth;
        _participantAuthorizer = participantAuthorizer;
        _relayService = relayService;
        _notifier = notifier;
    }

    [HttpGet]
    [Authorize(Policy = "UserAuthenticated")]
    public async Task<ActionResult<IReadOnlyList<SessionDto>>> GetSessions(CancellationToken cancellationToken)
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
        Guid.TryParse(userIdStr, out var callerId);
        var isAdmin = User.IsInRole("Admin");

        var query = _db.Sessions.AsNoTracking();
        if (!isAdmin)
            query = query.Where(s => s.ControllerUserId == callerId);

        var list = await query.OrderByDescending(s => s.CreatedAt).Take(100).ToListAsync(cancellationToken);
        return Ok(list.Select(EntityMappers.ToDto).ToList());
    }

    [HttpPost]
    [Authorize(Policy = "UserAuthenticated")]
    public async Task<ActionResult<SessionDto>> RequestSession(
        [FromBody] SessionRequestDto request,
        CancellationToken cancellationToken)
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
        if (!Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "operator";
        var isAdmin = User.IsInRole("Admin");

        var device = await _db.Devices.FirstOrDefaultAsync(d => d.Id == request.HostDeviceId, cancellationToken);
        if (device is null)
            return NotFound(new { error = "Target host device not found." });

        if (device.IsRevoked || !device.IsApproved)
        {
            _db.AuditEvents.Add(new AuditEventEntity
            {
                Id = Guid.NewGuid(),
                EventType = "SessionDenied",
                ActorUserId = userId,
                ActorEmail = email,
                TargetDeviceId = device.Id,
                Summary = $"Denied session request to {device.DisplayName}: device is {(device.IsRevoked ? "revoked" : "pending approval")}.",
                OccurredAt = DateTimeOffset.UtcNow
            });
            await _db.SaveChangesAsync(cancellationToken);
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Device is revoked or not approved for sessions." });
        }

        if (device.Status == DeviceStatus.Offline)
            return Conflict(new { error = "Target host device is offline." });

        var grant = await _db.DevicePermissions
            .FirstOrDefaultAsync(p => p.UserId == userId && p.DeviceId == device.Id, cancellationToken);

        var allowed = _sessionAuth.CanInitiateSession(
            device.IsApproved,
            device.IsRevoked,
            request.RequestUnattended,
            device.UnattendedAccessEnabled,
            grant?.AllowUnattendedAccess ?? false,
            grant?.Permissions ?? DevicePermission.None,
            isAdmin);

        var now = DateTimeOffset.UtcNow;
        if (!allowed)
        {
            var reason = request.RequestUnattended
                ? "Unattended access is not explicitly authorised for both device and user."
                : "Caller does not hold ViewScreen permission on this device.";

            var rejected = new SessionEntity
            {
                Id = Guid.NewGuid(),
                HostDeviceId = device.Id,
                ControllerUserId = userId,
                ControllerDeviceId = request.ControllerDeviceId ?? Guid.NewGuid(),
                ControllerDeviceName = string.IsNullOrWhiteSpace(request.ControllerDeviceName) ? "WINDOWS-CONTROLLER" : request.ControllerDeviceName.Trim(),
                State = SessionState.Rejected,
                RelayOnlyEnforced = true,
                RequestUnattended = request.RequestUnattended,
                CreatedAt = now,
                EndedAt = now,
                EndReason = reason
            };

            _db.Sessions.Add(rejected);
            var denyAudit = new AuditEventEntity
            {
                Id = Guid.NewGuid(),
                EventType = "SessionDenied",
                ActorUserId = userId,
                ActorEmail = email,
                TargetDeviceId = device.Id,
                SessionId = rejected.Id,
                Summary = $"Denied session to {device.DisplayName}: {reason}",
                OccurredAt = now
            };
            _db.AuditEvents.Add(denyAudit);
            await _db.SaveChangesAsync(cancellationToken);

            await _notifier.NotifySessionUpdatedAsync(EntityMappers.ToDto(rejected), cancellationToken);
            await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(denyAudit), cancellationToken);
            return StatusCode(StatusCodes.Status403Forbidden, new { error = reason, session = EntityMappers.ToDto(rejected) });
        }

        var session = new SessionEntity
        {
            Id = Guid.NewGuid(),
            HostDeviceId = device.Id,
            ControllerUserId = userId,
            ControllerDeviceId = request.ControllerDeviceId ?? Guid.NewGuid(),
            ControllerDeviceName = string.IsNullOrWhiteSpace(request.ControllerDeviceName) ? "WINDOWS-CONTROLLER" : request.ControllerDeviceName.Trim(),
            State = SessionState.Authorised,
            RelayOnlyEnforced = true,
            RequestUnattended = request.RequestUnattended,
            CreatedAt = now
        };

        _db.Sessions.Add(session);
        _db.SessionEvents.Add(new SessionEventEntity
        {
            Id = Guid.NewGuid(),
            SessionId = session.Id,
            PreviousState = SessionState.Created,
            NewState = SessionState.Authorised,
            ActorIdentity = email,
            Note = "Session authorised under relay-only policy.",
            OccurredAt = now
        });

        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "SessionAuthorised",
            ActorUserId = userId,
            ActorEmail = email,
            TargetDeviceId = device.Id,
            SessionId = session.Id,
            Summary = $"Authorised relay-only session {session.Id} targeting {device.DisplayName}.",
            OccurredAt = now
        };
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);

        var dto = EntityMappers.ToDto(session);
        await _notifier.NotifySessionUpdatedAsync(dto, cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);
        return Created(string.Empty, dto);
    }

    [HttpPost("{id:guid}/turn-credentials")]
    [Authorize]
    public async Task<ActionResult<TurnCredentialsDto>> GetTurnCredentials(
        Guid id,
        CancellationToken cancellationToken)
    {
        var verification = await _participantAuthorizer.VerifyParticipantAsync(User, id, cancellationToken);
        if (!verification.IsAuthorised)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = verification.FailureReason });
        }

        var provider = await _relayService.GetTurnCredentialProviderAsync(cancellationToken);
        if (!provider.IsConfigured)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new
            {
                error = "TURN relay is not configured on the backend. Media relay credentials cannot be issued until TURN host, realm, and server-side TURN_SHARED_SECRET are configured."
            });
        }

        var creds = provider.GenerateEphemeralCredentials(id, TimeSpan.FromMinutes(10));
        return Ok(creds);
    }

    [HttpPost("{id:guid}/transition")]
    [Authorize]
    public async Task<ActionResult<SessionDto>> TransitionSession(
        Guid id,
        [FromBody] TransitionSessionRequestDto request,
        CancellationToken cancellationToken)
    {
        var verification = await _participantAuthorizer.VerifyParticipantAsync(User, id, cancellationToken);
        if (!verification.IsAuthorised && !User.IsInRole("Admin"))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = verification.FailureReason });
        }

        var session = await _db.Sessions
            .Include(s => s.HostDevice)
            .FirstOrDefaultAsync(s => s.Id == id, cancellationToken);
        if (session is null)
            return NotFound(new { error = "Session not found." });

        if (session.HostDevice.IsRevoked && request.NextState != SessionState.Revoked)
            return Conflict(new { error = "Host device is revoked; session can only transition to Revoked." });

        if (request.NextState is SessionState.RelayConnecting or SessionState.Connected)
        {
            var provider = await _relayService.GetTurnCredentialProviderAsync(cancellationToken);
            if (!provider.IsConfigured)
            {
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new
                {
                    error = "TURN relay is not configured. Relayed media connections are unavailable."
                });
            }
        }

        if (!SessionStateTransitions.CanTransition(session.State, request.NextState))
            return Conflict(new { error = $"Invalid session state transition: {session.State} -> {request.NextState}" });

        var now = DateTimeOffset.UtcNow;
        var actor = verification.IsAuthorised
            ? verification.ActorIdentity
            : (User.FindFirst(ClaimTypes.Email)?.Value ?? "admin");

        if (request.NextState == SessionState.Connected)
        {
            var relayCheck = TurnRelayConfiguration.VerifySelectedCandidatePair(
                request.SelectedCandidatePair,
                IceTransportPolicy.RelayOnly);

            if (!relayCheck.IsRelayVerified)
            {
                var prev = session.State;
                session.State = SessionState.Failed;
                session.EndedAt = now;
                session.EndReason = relayCheck.Reason;

                _db.SessionEvents.Add(new SessionEventEntity
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    PreviousState = prev,
                    NewState = SessionState.Failed,
                    ActorIdentity = actor,
                    Note = relayCheck.Reason,
                    OccurredAt = now
                });

                var rejectAudit = new AuditEventEntity
                {
                    Id = Guid.NewGuid(),
                    EventType = "RelayCandidateRejected",
                    ActorEmail = actor,
                    TargetDeviceId = session.HostDeviceId,
                    SessionId = session.Id,
                    Summary = $"Aborted session {session.Id}: {relayCheck.Reason}",
                    OccurredAt = now
                };
                _db.AuditEvents.Add(rejectAudit);
                await _db.SaveChangesAsync(cancellationToken);

                await _notifier.NotifySessionUpdatedAsync(EntityMappers.ToDto(session), cancellationToken);
                await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(rejectAudit), cancellationToken);
                return BadRequest(new { error = relayCheck.Reason, session = EntityMappers.ToDto(session) });
            }

            session.SelectedCandidateType = "relay";
            session.SelectedRelayAddress = request.SelectedCandidatePair!.RelayServerAddress;
            session.ConnectedAt = now;
            session.HostDevice.Status = DeviceStatus.InSession;
            await _notifier.NotifyDeviceUpdatedAsync(EntityMappers.ToDto(session.HostDevice), cancellationToken);
        }

        var oldState = session.State;
        session.State = request.NextState;
        if (SessionStateTransitions.IsTerminal(request.NextState) || request.NextState == SessionState.Disconnected)
        {
            if (SessionStateTransitions.IsTerminal(request.NextState))
                session.EndedAt = now;

            session.EndReason = string.IsNullOrWhiteSpace(request.Reason)
                ? $"Transitioned to {request.NextState}"
                : request.Reason.Trim();

            if (session.HostDevice.Status == DeviceStatus.InSession)
            {
                session.HostDevice.Status = DeviceStatus.Online;
                await _notifier.NotifyDeviceUpdatedAsync(EntityMappers.ToDto(session.HostDevice), cancellationToken);
            }
        }

        _db.SessionEvents.Add(new SessionEventEntity
        {
            Id = Guid.NewGuid(),
            SessionId = session.Id,
            PreviousState = oldState,
            NewState = request.NextState,
            ActorIdentity = actor,
            Note = request.Reason ?? $"Transitioned to {request.NextState}",
            OccurredAt = now
        });

        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = $"Session{request.NextState}",
            ActorEmail = actor,
            TargetDeviceId = session.HostDeviceId,
            SessionId = session.Id,
            Summary = $"Session {session.Id} transitioned {oldState} -> {request.NextState}.",
            OccurredAt = now
        };
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);

        var dto = EntityMappers.ToDto(session);
        await _notifier.NotifySessionUpdatedAsync(dto, cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);
        return Ok(dto);
    }
}
