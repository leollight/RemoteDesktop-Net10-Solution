using RemoteDesktop.Contracts.Signalling;

namespace RemoteDesktop.Contracts.Sessions;

public enum SessionState
{
    Created = 0,
    AuthorisationPending = 1,
    Authorised = 2,
    RelayConnecting = 3,
    Connected = 4,
    Disconnected = 5,
    Completed = 6,
    Rejected = 7,
    TimedOut = 8,
    Cancelled = 9,
    Failed = 10,
    Revoked = 11
}

public static class SessionStateTransitions
{
    private static readonly Dictionary<SessionState, SessionState[]> Allowed = new()
    {
        [SessionState.Created] = [SessionState.AuthorisationPending, SessionState.Authorised, SessionState.Rejected, SessionState.Cancelled, SessionState.Failed],
        [SessionState.AuthorisationPending] = [SessionState.Authorised, SessionState.Rejected, SessionState.TimedOut, SessionState.Cancelled, SessionState.Revoked],
        [SessionState.Authorised] = [SessionState.RelayConnecting, SessionState.Cancelled, SessionState.Revoked, SessionState.Failed],
        [SessionState.RelayConnecting] = [SessionState.Connected, SessionState.Failed, SessionState.TimedOut, SessionState.Cancelled, SessionState.Revoked],
        [SessionState.Connected] = [SessionState.Disconnected, SessionState.Revoked, SessionState.Failed],
        [SessionState.Disconnected] = [SessionState.Completed, SessionState.RelayConnecting, SessionState.Revoked],
        [SessionState.Completed] = [],
        [SessionState.Rejected] = [],
        [SessionState.TimedOut] = [],
        [SessionState.Cancelled] = [],
        [SessionState.Failed] = [],
        [SessionState.Revoked] = []
    };

    public static bool CanTransition(SessionState current, SessionState next) =>
        Allowed.TryGetValue(current, out var validNext) && validNext.Contains(next);

    public static bool IsTerminal(SessionState state) =>
        state is SessionState.Completed or SessionState.Rejected or SessionState.TimedOut or SessionState.Cancelled or SessionState.Failed or SessionState.Revoked;
}

public sealed record SessionDto(
    Guid Id,
    Guid HostDeviceId,
    Guid ControllerUserId,
    Guid ControllerDeviceId,
    string ControllerDeviceName,
    SessionState State,
    bool RelayOnlyEnforced,
    string? SelectedCandidateType,
    bool RequestUnattended,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ConnectedAt,
    DateTimeOffset? EndedAt,
    string? EndReason);

public sealed record SessionRequestDto(
    Guid HostDeviceId,
    Guid? ControllerDeviceId,
    string ControllerDeviceName,
    bool RequestUnattended);

public sealed record TransitionSessionRequestDto(
    SessionState NextState,
    SelectedCandidatePairDto? SelectedCandidatePair,
    string? Reason);

public sealed record SessionTerminationDto(
    Guid SessionId,
    string Reason);

public sealed record TurnCredentialsDto(
    IReadOnlyList<string> Urls,
    string Username,
    string Credential,
    DateTimeOffset ExpiresAt,
    bool RelayOnly,
    string IceTransportPolicy);
