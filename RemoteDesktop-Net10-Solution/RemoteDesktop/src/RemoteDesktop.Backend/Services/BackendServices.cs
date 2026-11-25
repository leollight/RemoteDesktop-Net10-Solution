using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Configuration;
using RemoteDesktop.Backend.Hubs;
using RemoteDesktop.Contracts.Common;
using RemoteDesktop.Contracts.Configuration;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Sessions;
using RemoteDesktop.Infrastructure.Persistence;
using RemoteDesktop.Security;

namespace RemoteDesktop.Backend.Services;

public sealed record SessionParticipantVerification(
    bool IsAuthorised,
    string ParticipantRole,
    string ActorIdentity,
    string FailureReason);

public interface ISessionParticipantAuthorizer
{
    Task<SessionParticipantVerification> VerifyParticipantAsync(
        ClaimsPrincipal? principal,
        Guid sessionId,
        CancellationToken cancellationToken);
}

public sealed class SessionParticipantAuthorizer : ISessionParticipantAuthorizer
{
    private readonly ApplicationDbContext _db;

    public SessionParticipantAuthorizer(ApplicationDbContext db) => _db = db;

    public async Task<SessionParticipantVerification> VerifyParticipantAsync(
        ClaimsPrincipal? principal,
        Guid sessionId,
        CancellationToken cancellationToken)
    {
        if (principal?.Identity?.IsAuthenticated != true)
            return new(false, string.Empty, string.Empty, "Caller is not authenticated.");

        var session = await _db.Sessions
            .Include(s => s.HostDevice)
            .FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);

        if (session is null)
            return new(false, string.Empty, string.Empty, "Session does not exist.");

        if (SessionStateTransitions.IsTerminal(session.State) || session.State == SessionState.Created)
            return new(false, string.Empty, string.Empty, $"Session state '{session.State}' is not active for signalling.");

        if (session.HostDevice.IsRevoked || !session.HostDevice.IsApproved)
            return new(false, string.Empty, string.Empty, "Target host device is revoked or not approved.");

        var jti = principal.FindFirst("jti")?.Value;
        if (!string.IsNullOrWhiteSpace(jti))
        {
            var isRevokedToken = await _db.RevokedCredentials
                .AnyAsync(r => r.CredentialJti == jti, cancellationToken);
            if (isRevokedToken)
                return new(false, string.Empty, string.Empty, "Caller credential has been revoked.");
        }

        var participantType = principal.FindFirst("participant_type")?.Value;
        if (string.Equals(participantType, "device", StringComparison.OrdinalIgnoreCase))
        {
            var deviceClaim = principal.FindFirst("device_id")?.Value;
            if (!Guid.TryParse(deviceClaim, out var deviceId) || deviceId != session.HostDeviceId)
                return new(false, string.Empty, string.Empty, "Authenticated device is not the host of this session.");

            return new(true, "HostDevice", session.HostDevice.DisplayName, string.Empty);
        }

        var userClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.FindFirst("sub")?.Value;
        if (!Guid.TryParse(userClaim, out var userId))
            return new(false, string.Empty, string.Empty, "User identity claim is missing.");

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user is null || user.IsDisabled)
            return new(false, string.Empty, string.Empty, "User account is missing or disabled.");

        if (session.ControllerUserId != userId)
            return new(false, string.Empty, string.Empty, "User is not a participant in this session.");

        return new(true, "ControllerUser", user.Email, string.Empty);
    }
}

public sealed class SignallingConnectionTracker
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<Guid, string>> _memberships = new();

    public void RegisterMembership(string connectionId, Guid sessionId, string participantRole)
    {
        var sessions = _memberships.GetOrAdd(connectionId, _ => new ConcurrentDictionary<Guid, string>());
        sessions[sessionId] = participantRole;
    }

    public bool IsSessionMember(string connectionId, Guid sessionId) =>
        _memberships.TryGetValue(connectionId, out var sessions) && sessions.ContainsKey(sessionId);

    public void RemoveConnection(string connectionId) => _memberships.TryRemove(connectionId, out _);
}

public sealed record DeviceChallengeRecord(Guid DeviceId, string NonceBase64, DateTimeOffset ExpiresAt);

public interface IDeviceChallengeStore
{
    DeviceChallengeRecord IssueChallenge(Guid deviceId);
    bool TryConsumeChallenge(Guid deviceId, string nonceBase64);
}

public sealed class InMemoryDeviceChallengeStore : IDeviceChallengeStore
{
    private readonly ConcurrentDictionary<(Guid DeviceId, string Nonce), DateTimeOffset> _challenges = new();

    public DeviceChallengeRecord IssueChallenge(Guid deviceId)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kv in _challenges)
        {
            if (kv.Value <= now)
                _challenges.TryRemove(kv.Key, out _);
        }

        var nonceBytes = RandomNumberGenerator.GetBytes(32);
        var nonceBase64 = Convert.ToBase64String(nonceBytes);
        var expiresAt = now.AddSeconds(60);
        _challenges[(deviceId, nonceBase64)] = expiresAt;
        return new DeviceChallengeRecord(deviceId, nonceBase64, expiresAt);
    }

    public bool TryConsumeChallenge(Guid deviceId, string nonceBase64)
    {
        if (!_challenges.TryRemove((deviceId, nonceBase64), out var expiresAt))
            return false;

        return expiresAt > DateTimeOffset.UtcNow;
    }
}

public interface IEffectiveRelayService
{
    Task<RelayOptions> GetEffectiveOptionsAsync(CancellationToken cancellationToken);
    Task<ITurnCredentialProvider> GetTurnCredentialProviderAsync(CancellationToken cancellationToken);
}

public sealed class EffectiveRelayService : IEffectiveRelayService
{
    private readonly ApplicationDbContext _db;
    private readonly RelayOptions _baseOptions;

    public EffectiveRelayService(ApplicationDbContext db, RelayOptions baseOptions)
    {
        _db = db;
        _baseOptions = baseOptions;
    }

    public async Task<RelayOptions> GetEffectiveOptionsAsync(CancellationToken cancellationToken)
    {
        var stored = await _db.DeploymentSettings.FirstOrDefaultAsync(x => x.Id == 1, cancellationToken);
        if (stored is null)
            return _baseOptions;

        return new RelayOptions
        {
            Host = string.IsNullOrWhiteSpace(stored.TurnHost) ? _baseOptions.Host : stored.TurnHost,
            Port = stored.TurnPort is > 0 and < 65536 ? stored.TurnPort : _baseOptions.Port,
            Transport = string.IsNullOrWhiteSpace(stored.TurnTransport) ? _baseOptions.Transport : stored.TurnTransport,
            Realm = string.IsNullOrWhiteSpace(stored.TurnRealm) ? _baseOptions.Realm : stored.TurnRealm,
            PublicBaseUrl = string.IsNullOrWhiteSpace(stored.BackendBaseUrl) ? _baseOptions.PublicBaseUrl : stored.BackendBaseUrl,
            RelayOnly = true,
            SharedSecret = _baseOptions.SharedSecret
        };
    }

    public async Task<ITurnCredentialProvider> GetTurnCredentialProviderAsync(CancellationToken cancellationToken)
    {
        var effective = await GetEffectiveOptionsAsync(cancellationToken);
        return new TurnCredentialProvider(effective.SharedSecret, effective.BuildTurnUris());
    }
}

public sealed class ControlPlaneNotifier
{
    private readonly IHubContext<SignallingHub> _hubContext;

    public ControlPlaneNotifier(IHubContext<SignallingHub> hubContext) => _hubContext = hubContext;

    public Task NotifyDeviceUpdatedAsync(DeviceDto device, CancellationToken ct) =>
        _hubContext.Clients.Group(SignallingHub.ControlPlaneGroup).SendAsync("DeviceUpdated", device, ct);

    public Task NotifySessionUpdatedAsync(SessionDto session, CancellationToken ct) =>
        _hubContext.Clients.Group(SignallingHub.ControlPlaneGroup).SendAsync("SessionUpdated", session, ct);

    public Task NotifyPermissionUpdatedAsync(PermissionDto permission, CancellationToken ct) =>
        _hubContext.Clients.Group(SignallingHub.ControlPlaneGroup).SendAsync("PermissionUpdated", permission, ct);

    public Task NotifyAuditCreatedAsync(AuditEventDto audit, CancellationToken ct) =>
        _hubContext.Clients.Group(SignallingHub.ControlPlaneGroup).SendAsync("AuditCreated", audit, ct);

    public Task NotifySessionRevokedAsync(Guid sessionId, string reason, CancellationToken ct) =>
        _hubContext.Clients.Group(SignallingHub.SessionGroupName(sessionId))
            .SendAsync("SessionRevoked", new SessionTerminationDto(sessionId, reason), ct);
}

public static class EntityMappers
{
    public static string HashToken(string rawToken)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken.Trim()));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static DeviceDto ToDto(DeviceEntity device, string? activeFingerprint = null)
    {
        var fp = activeFingerprint
            ?? device.Keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault(k => k.RevokedAt == null)?.Fingerprint
            ?? device.Keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault()?.Fingerprint
            ?? string.Empty;

        return new DeviceDto(
            device.Id,
            device.DisplayName,
            device.OperatingSystem,
            device.AppVersion,
            fp,
            device.Status,
            device.IsApproved,
            device.IsRevoked,
            device.UnattendedAccessEnabled,
            device.RegisteredAt,
            device.LastOnlineAt,
            new DeviceCapabilitiesDto(
                device.MonitorCount,
                device.SupportsWindowsGraphicsCapture,
                device.SupportsDxgiDuplication,
                device.PreferredEncoder,
                device.SupportsHardwareEncoding,
                device.SupportsAudioCapture));
    }

    public static SessionDto ToDto(SessionEntity session) =>
        new(
            session.Id,
            session.HostDeviceId,
            session.ControllerUserId,
            session.ControllerDeviceId,
            session.ControllerDeviceName,
            session.State,
            session.RelayOnlyEnforced,
            session.SelectedCandidateType,
            session.RequestUnattended,
            session.CreatedAt,
            session.ConnectedAt,
            session.EndedAt,
            session.EndReason);

    public static AuditEventDto ToDto(AuditEventEntity evt) =>
        new(
            evt.Id,
            evt.EventType,
            evt.ActorEmail,
            evt.TargetDeviceId,
            evt.SessionId,
            evt.Summary,
            evt.OccurredAt);
}
