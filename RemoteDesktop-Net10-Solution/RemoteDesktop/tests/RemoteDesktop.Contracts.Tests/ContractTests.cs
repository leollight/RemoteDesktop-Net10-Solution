using System.Text.Json;
using RemoteDesktop.Contracts.Ipc;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Sessions;
using RemoteDesktop.Contracts.Signalling;
using Xunit;

namespace RemoteDesktop.Contracts.Tests;

public sealed class ContractTests
{
    [Fact]
    public void SessionStateTransitions_EnforceLifecycle()
    {
        Assert.False(SessionStateTransitions.CanTransition(SessionState.Created, SessionState.Connected));
        Assert.True(SessionStateTransitions.CanTransition(SessionState.Authorised, SessionState.RelayConnecting));
        Assert.True(SessionStateTransitions.CanTransition(SessionState.RelayConnecting, SessionState.Connected));
        Assert.True(SessionStateTransitions.IsTerminal(SessionState.Revoked));
        Assert.False(SessionStateTransitions.CanTransition(SessionState.Revoked, SessionState.Connected));
    }

    [Fact]
    public void AgentIpcEnvelope_RoundTripsWithJsonSerialization()
    {
        var grant = new SessionGrantPayload(Guid.NewGuid(), Guid.NewGuid(), DevicePermission.ViewScreen | DevicePermission.ControlMouse, RelayOnlyEnforced: true);
        var envelope = new AgentIpcEnvelope(
            ProtocolVersion: 1,
            MessageType: AgentIpcMessageType.SessionAuthorisationGrant,
            CorrelationId: "corr-1",
            TimestampUtc: DateTimeOffset.UtcNow,
            PayloadJson: JsonSerializer.Serialize(grant));

        var raw = JsonSerializer.Serialize(envelope);
        var decoded = JsonSerializer.Deserialize<AgentIpcEnvelope>(raw);

        Assert.NotNull(decoded);
        Assert.Equal(AgentIpcMessageType.SessionAuthorisationGrant, decoded!.MessageType);
        var decodedGrant = JsonSerializer.Deserialize<SessionGrantPayload>(decoded.PayloadJson);
        Assert.Equal(grant.SessionId, decodedGrant!.SessionId);
        Assert.True(decodedGrant.GrantedPermissions.HasFlag(DevicePermission.ControlMouse));
    }

    [Fact]
    public void SelectedCandidatePairDto_SerializesLocalAndRemoteTypes()
    {
        var pair = new SelectedCandidatePairDto(
            Guid.NewGuid(),
            "relay",
            "relay",
            "udp",
            "198.51.100.2:49152",
            "succeeded");

        var json = JsonSerializer.Serialize(pair);
        var restored = JsonSerializer.Deserialize<SelectedCandidatePairDto>(json);
        Assert.Equal("relay", restored!.LocalCandidateType);
        Assert.Equal("relay", restored.RemoteCandidateType);
    }
}
