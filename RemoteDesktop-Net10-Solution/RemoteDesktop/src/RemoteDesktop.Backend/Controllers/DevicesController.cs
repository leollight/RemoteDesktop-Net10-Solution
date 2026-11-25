using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Contracts.Authentication;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Contracts.Sessions;
using RemoteDesktop.Infrastructure.Persistence;
using RemoteDesktop.Security;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api/devices")]
public sealed class DevicesController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IDeviceIdentityService _identityService;
    private readonly IDeviceChallengeStore _challengeStore;
    private readonly ITokenService _tokenService;
    private readonly ControlPlaneNotifier _notifier;

    public DevicesController(
        ApplicationDbContext db,
        IDeviceIdentityService identityService,
        IDeviceChallengeStore challengeStore,
        ITokenService tokenService,
        ControlPlaneNotifier notifier)
    {
        _db = db;
        _identityService = identityService;
        _challengeStore = challengeStore;
        _tokenService = tokenService;
        _notifier = notifier;
    }

    [HttpGet]
    [Authorize(Policy = "UserAuthenticated")]
    public async Task<ActionResult<IReadOnlyList<DeviceDto>>> GetDevices(CancellationToken cancellationToken)
    {
        var devices = await _db.Devices
            .Include(d => d.Keys)
            .OrderByDescending(d => d.RegisteredAt)
            .ToListAsync(cancellationToken);

        return Ok(devices.Select(d => EntityMappers.ToDto(d)).ToList());
    }

    [HttpPost("enrolment-token")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<EnrolmentTokenDto>> IssueEnrolmentToken(CancellationToken cancellationToken)
    {
        var userIdStr = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
        Guid.TryParse(userIdStr, out var userId);
        var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "admin";

        var rawToken = $"ENR-{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}";
        var now = DateTimeOffset.UtcNow;
        var entity = new EnrolmentTokenEntity
        {
            Id = Guid.NewGuid(),
            TokenHash = EntityMappers.HashToken(rawToken),
            TokenPreview = $"{rawToken[..8]}…",
            IssuedByUserId = userId,
            IssuedByEmail = email,
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(15)
        };

        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "EnrolmentTokenIssued",
            ActorUserId = userId == Guid.Empty ? null : userId,
            ActorEmail = email,
            Summary = "Issued single-use 15-minute device enrolment token.",
            OccurredAt = now
        };

        _db.EnrolmentTokens.Add(entity);
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);

        return Created(string.Empty, new EnrolmentTokenDto(entity.Id, rawToken, entity.IssuedByEmail, entity.ExpiresAt, Used: false));
    }

    [HttpPost("enrol")]
    [AllowAnonymous]
    public async Task<ActionResult<DeviceDto>> EnrolDevice(
        [FromBody] DeviceRegistrationDto request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.DisplayName)
            || string.IsNullOrWhiteSpace(request.PublicKeyBase64)
            || string.IsNullOrWhiteSpace(request.EnrolmentToken))
        {
            return BadRequest(new { error = "DisplayName, PublicKeyBase64, and EnrolmentToken are required." });
        }

        string fingerprint;
        try
        {
            fingerprint = _identityService.ComputeFingerprint(request.PublicKeyBase64);
        }
        catch
        {
            return BadRequest(new { error = "PublicKeyBase64 must be valid SubjectPublicKeyInfo base64." });
        }

        var now = DateTimeOffset.UtcNow;
        var tokenHash = EntityMappers.HashToken(request.EnrolmentToken);
        var tokenEntity = await _db.EnrolmentTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && t.UsedAt == null && t.ExpiresAt > now, cancellationToken);

        if (tokenEntity is null)
        {
            _db.AuditEvents.Add(new AuditEventEntity
            {
                Id = Guid.NewGuid(),
                EventType = "EnrolmentRejected",
                ActorEmail = request.DisplayName.Trim(),
                Summary = $"Rejected device enrolment for {request.DisplayName.Trim()}: invalid or expired enrolment token.",
                OccurredAt = now
            });
            await _db.SaveChangesAsync(cancellationToken);
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Invalid or expired enrolment token." });
        }

        if (await _db.DeviceKeys.AnyAsync(k => k.Fingerprint == fingerprint, cancellationToken))
        {
            return Conflict(new { error = "A device with this cryptographic public key fingerprint is already enrolled." });
        }

        var device = new DeviceEntity
        {
            Id = Guid.NewGuid(),
            DisplayName = request.DisplayName.Trim(),
            OperatingSystem = string.IsNullOrWhiteSpace(request.OperatingSystem) ? "Windows" : request.OperatingSystem.Trim(),
            AppVersion = string.IsNullOrWhiteSpace(request.AppVersion) ? "1.0.0" : request.AppVersion.Trim(),
            Status = DeviceStatus.PendingApproval,
            IsApproved = false,
            IsRevoked = false,
            UnattendedAccessEnabled = false,
            MonitorCount = Math.Clamp(request.Capabilities.MonitorCount, 1, 16),
            SupportsWindowsGraphicsCapture = request.Capabilities.SupportsWindowsGraphicsCapture,
            SupportsDxgiDuplication = request.Capabilities.SupportsDxgiDuplication,
            PreferredEncoder = request.Capabilities.PreferredEncoder,
            SupportsHardwareEncoding = request.Capabilities.SupportsHardwareEncoding,
            SupportsAudioCapture = request.Capabilities.SupportsAudioCapture,
            RegisteredAt = now,
            LastOnlineAt = now
        };

        var keyEntity = new DeviceKeyEntity
        {
            Id = Guid.NewGuid(),
            DeviceId = device.Id,
            PublicKeyBase64 = request.PublicKeyBase64.Trim(),
            Fingerprint = fingerprint,
            CreatedAt = now
        };

        tokenEntity.UsedAt = now;
        tokenEntity.UsedByDeviceId = device.Id;

        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "DeviceEnrolled",
            ActorEmail = tokenEntity.IssuedByEmail,
            TargetDeviceId = device.Id,
            Summary = $"Device {device.DisplayName} enrolled ECDSA key ({fingerprint[..Math.Min(12, fingerprint.Length)]}…) and entered PendingApproval.",
            OccurredAt = now
        };

        _db.Devices.Add(device);
        _db.DeviceKeys.Add(keyEntity);
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);

        var dto = EntityMappers.ToDto(device, fingerprint);
        await _notifier.NotifyDeviceUpdatedAsync(dto, cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);
        return Created(string.Empty, dto);
    }

    [HttpPost("challenge")]
    [AllowAnonymous]
    public async Task<ActionResult<DeviceChallengeDto>> IssueChallenge(
        [FromBody] DeviceChallengeRequestDto request,
        CancellationToken cancellationToken)
    {
        var device = await _db.Devices.AsNoTracking()
            .FirstOrDefaultAsync(d => d.Id == request.DeviceId, cancellationToken);

        if (device is null)
            return NotFound(new { error = "Enrolled device not found." });

        if (device.IsRevoked)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Device has been revoked." });

        var challenge = _challengeStore.IssueChallenge(device.Id);
        return Ok(new DeviceChallengeDto(challenge.DeviceId, challenge.NonceBase64, challenge.ExpiresAt));
    }

    [HttpPost("authenticate")]
    [AllowAnonymous]
    public async Task<ActionResult<DeviceAuthResponseDto>> AuthenticateDevice(
        [FromBody] DeviceChallengeResponseDto request,
        CancellationToken cancellationToken)
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var device = await _db.Devices
            .Include(d => d.Keys)
            .FirstOrDefaultAsync(d => d.Id == request.DeviceId, cancellationToken);

        if (device is null)
            return NotFound(new { error = "Device not found." });

        if (device.IsRevoked)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Device credentials have been revoked." });

        if (!device.IsApproved)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Device is awaiting explicit administrator approval." });

        if (!_challengeStore.TryConsumeChallenge(request.DeviceId, request.NonceBase64))
            return Unauthorized(new { error = "Challenge nonce is missing, expired, or already used." });

        var activeKey = device.Keys
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefault(k => k.RevokedAt == null);

        if (activeKey is null)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "No active public key is bound to this device." });

        byte[] nonceBytes;
        byte[] sigBytes;
        try
        {
            nonceBytes = Convert.FromBase64String(request.NonceBase64);
            sigBytes = Convert.FromBase64String(request.SignatureBase64);
        }
        catch
        {
            return BadRequest(new { error = "Invalid base64 challenge or signature." });
        }

        if (!_identityService.VerifyChallengeSignature(activeKey.PublicKeyBase64, nonceBytes, sigBytes))
        {
            _db.AuthenticationEvents.Add(new AuthenticationEventEntity
            {
                Id = Guid.NewGuid(),
                SubjectType = "Device",
                SubjectIdentifier = device.Id.ToString(),
                Succeeded = false,
                FailureReason = "ECDSA challenge signature verification failed.",
                RemoteIp = remoteIp,
                OccurredAt = DateTimeOffset.UtcNow
            });
            await _db.SaveChangesAsync(cancellationToken);
            return Unauthorized(new { error = "Device signature verification failed." });
        }

        device.LastOnlineAt = DateTimeOffset.UtcNow;
        if (device.Status == DeviceStatus.Offline)
            device.Status = DeviceStatus.Online;

        _db.AuthenticationEvents.Add(new AuthenticationEventEntity
        {
            Id = Guid.NewGuid(),
            SubjectType = "Device",
            SubjectIdentifier = device.Id.ToString(),
            Succeeded = true,
            FailureReason = string.Empty,
            RemoteIp = remoteIp,
            OccurredAt = DateTimeOffset.UtcNow
        });
        await _db.SaveChangesAsync(cancellationToken);
        await _notifier.NotifyDeviceUpdatedAsync(EntityMappers.ToDto(device, activeKey.Fingerprint), cancellationToken);

        var (token, expiresAt, _) = _tokenService.IssueDeviceToken(device.Id, device.DisplayName, activeKey.Fingerprint);
        return Ok(new DeviceAuthResponseDto(device.Id, device.IsApproved, device.IsRevoked, token, expiresAt));
    }

    [HttpPost("{id:guid}/approve")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<DeviceDto>> ApproveDevice(Guid id, CancellationToken cancellationToken)
    {
        var device = await _db.Devices.Include(d => d.Keys).FirstOrDefaultAsync(d => d.Id == id, cancellationToken);
        if (device is null) return NotFound(new { error = "Device not found." });
        if (device.IsRevoked) return Conflict(new { error = "Revoked devices cannot be re-approved; re-enrol with a new key." });

        device.IsApproved = true;
        device.Status = DeviceStatus.Online;
        device.LastOnlineAt = DateTimeOffset.UtcNow;

        var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "admin";
        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "DeviceApproved",
            ActorEmail = email,
            TargetDeviceId = device.Id,
            Summary = $"Approved trusted device {device.DisplayName}.",
            OccurredAt = DateTimeOffset.UtcNow
        };
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);

        var dto = EntityMappers.ToDto(device);
        await _notifier.NotifyDeviceUpdatedAsync(dto, cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);
        return Ok(dto);
    }

    [HttpPost("{id:guid}/revoke")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<DeviceDto>> RevokeDevice(Guid id, CancellationToken cancellationToken)
    {
        var device = await _db.Devices.Include(d => d.Keys).FirstOrDefaultAsync(d => d.Id == id, cancellationToken);
        if (device is null) return NotFound(new { error = "Device not found." });

        var now = DateTimeOffset.UtcNow;
        device.IsRevoked = true;
        device.IsApproved = false;
        device.UnattendedAccessEnabled = false;
        device.Status = DeviceStatus.Revoked;

        foreach (var key in device.Keys.Where(k => k.RevokedAt == null))
        {
            key.RevokedAt = now;
        }

        var activeSessions = await _db.Sessions
            .Where(s => s.HostDeviceId == device.Id
                && s.State != SessionState.Completed
                && s.State != SessionState.Rejected
                && s.State != SessionState.TimedOut
                && s.State != SessionState.Cancelled
                && s.State != SessionState.Failed
                && s.State != SessionState.Revoked)
            .ToListAsync(cancellationToken);

        var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "admin";
        foreach (var s in activeSessions)
        {
            var prev = s.State;
            s.State = SessionState.Revoked;
            s.EndedAt = now;
            s.EndReason = "Host device credentials revoked by administrator";
            _db.SessionEvents.Add(new SessionEventEntity
            {
                Id = Guid.NewGuid(),
                SessionId = s.Id,
                PreviousState = prev,
                NewState = SessionState.Revoked,
                ActorIdentity = email,
                Note = s.EndReason,
                OccurredAt = now
            });
        }

        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "DeviceRevoked",
            ActorEmail = email,
            TargetDeviceId = device.Id,
            Summary = $"Revoked device {device.DisplayName} and terminated {activeSessions.Count} active session(s).",
            OccurredAt = now
        };
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);

        foreach (var s in activeSessions)
        {
            await _notifier.NotifySessionRevokedAsync(s.Id, s.EndReason ?? "Device revoked", cancellationToken);
            await _notifier.NotifySessionUpdatedAsync(EntityMappers.ToDto(s), cancellationToken);
        }

        var dto = EntityMappers.ToDto(device);
        await _notifier.NotifyDeviceUpdatedAsync(dto, cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);
        return Ok(dto);
    }

    [HttpPatch("{id:guid}/unattended")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<DeviceDto>> ToggleUnattended(
        Guid id,
        [FromBody] ToggleUnattendedDto request,
        CancellationToken cancellationToken)
    {
        var device = await _db.Devices.Include(d => d.Keys).FirstOrDefaultAsync(d => d.Id == id, cancellationToken);
        if (device is null) return NotFound(new { error = "Device not found." });
        if (!device.IsApproved || device.IsRevoked)
            return Conflict(new { error = "Device must be approved and active before enabling unattended access." });

        device.UnattendedAccessEnabled = request.Enabled;
        var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "admin";
        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "DevicePolicyUpdated",
            ActorEmail = email,
            TargetDeviceId = device.Id,
            Summary = $"{(request.Enabled ? "Enabled" : "Disabled")} unattended access policy on {device.DisplayName}.",
            OccurredAt = DateTimeOffset.UtcNow
        };
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);

        var dto = EntityMappers.ToDto(device);
        await _notifier.NotifyDeviceUpdatedAsync(dto, cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);
        return Ok(dto);
    }

    [HttpPatch("{id:guid}/status")]
    [Authorize]
    public async Task<ActionResult<DeviceDto>> UpdateStatus(
        Guid id,
        [FromBody] UpdateDeviceStatusDto request,
        CancellationToken cancellationToken)
    {
        var participantType = User.FindFirst("participant_type")?.Value;
        if (string.Equals(participantType, "device", StringComparison.OrdinalIgnoreCase))
        {
            var claimId = User.FindFirst("device_id")?.Value;
            if (!Guid.TryParse(claimId, out var devClaimId) || devClaimId != id)
                return Forbid();
        }
        else if (!User.IsInRole("Admin"))
        {
            return Forbid();
        }

        var device = await _db.Devices.Include(d => d.Keys).FirstOrDefaultAsync(d => d.Id == id, cancellationToken);
        if (device is null) return NotFound(new { error = "Device not found." });
        if (!device.IsApproved || device.IsRevoked)
            return Conflict(new { error = "Cannot update online status for unapproved or revoked devices." });

        if (request.Status is not (DeviceStatus.Online or DeviceStatus.Offline))
            return BadRequest(new { error = "Status must be Online or Offline." });

        device.Status = request.Status;
        if (request.Status == DeviceStatus.Online)
            device.LastOnlineAt = DateTimeOffset.UtcNow;

        await _db.SaveChangesAsync(cancellationToken);
        var dto = EntityMappers.ToDto(device);
        await _notifier.NotifyDeviceUpdatedAsync(dto, cancellationToken);
        return Ok(dto);
    }
}
