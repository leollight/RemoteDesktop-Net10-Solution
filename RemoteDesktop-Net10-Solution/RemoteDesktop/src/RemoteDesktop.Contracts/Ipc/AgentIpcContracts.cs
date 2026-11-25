using RemoteDesktop.Contracts.Permissions;

namespace RemoteDesktop.Contracts.Ipc;

public enum AgentIpcMessageType
{
    AgentHello = 1,
    ServiceAck = 2,
    SessionAuthorisationGrant = 3,
    PermissionUpdate = 4,
    SessionRevocationCommand = 5,
    Heartbeat = 6,
    MediaStatusReport = 7,
    Error = 8
}

public sealed record AgentIpcEnvelope(
    int ProtocolVersion,
    AgentIpcMessageType MessageType,
    string CorrelationId,
    DateTimeOffset TimestampUtc,
    string PayloadJson);

public sealed record AgentHelloPayload(
    int ProcessId,
    int WindowsSessionId,
    string InteractiveUsername,
    string NonceProofHmac,
    bool CaptureSupported,
    bool InputInjectionSupported,
    bool WebRtcMediaSupported);

public sealed record ServiceAckPayload(
    bool Accepted,
    Guid DeviceId,
    string Message);

public sealed record SessionGrantPayload(
    Guid SessionId,
    Guid ControllerUserId,
    DevicePermission GrantedPermissions,
    bool RelayOnlyEnforced);

public sealed record SessionRevokePayload(
    Guid SessionId,
    string Reason);

public sealed record AgentHeartbeatPayload(
    int WindowsSessionId,
    Guid? ActiveSessionId,
    DateTimeOffset SentAtUtc);

public sealed record MediaStatusPayload(
    Guid SessionId,
    bool CaptureImplemented,
    bool AudioImplemented,
    bool InputInjectionImplemented,
    bool WebRtcEngineImplemented,
    string Detail);
