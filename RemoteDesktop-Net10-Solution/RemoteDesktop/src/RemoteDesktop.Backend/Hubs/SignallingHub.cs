using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Contracts.Signalling;
using RemoteDesktop.Media;

namespace RemoteDesktop.Backend.Hubs;

[Authorize]
public sealed class SignallingHub : Hub
{
    public const string ControlPlaneGroup = "control-plane-observers";

    private readonly ISessionParticipantAuthorizer _authorizer;
    private readonly SignallingConnectionTracker _tracker;

    public SignallingHub(
        ISessionParticipantAuthorizer authorizer,
        SignallingConnectionTracker tracker)
    {
        _authorizer = authorizer;
        _tracker = tracker;
    }

    public static string SessionGroupName(Guid sessionId) => $"session-{sessionId:N}";

    public async Task SubscribeControlEvents()
    {
        var participantType = Context.User?.FindFirst("participant_type")?.Value;
        if (!string.Equals(participantType, "user", StringComparison.OrdinalIgnoreCase))
        {
            throw new HubException("Only authenticated human control-plane users may subscribe to dashboard control events.");
        }

        await Groups.AddToGroupAsync(Context.ConnectionId, ControlPlaneGroup);
    }

    public async Task JoinSessionChannel(Guid sessionId)
    {
        var verification = await _authorizer.VerifyParticipantAsync(Context.User, sessionId, Context.ConnectionAborted);
        if (!verification.IsAuthorised)
        {
            throw new HubException($"Session channel access denied: {verification.FailureReason}");
        }

        _tracker.RegisterMembership(Context.ConnectionId, sessionId, verification.ParticipantRole);
        await Groups.AddToGroupAsync(Context.ConnectionId, SessionGroupName(sessionId));
    }

    public async Task ForwardOffer(OfferDto offer)
    {
        await EnsureActiveMembershipAsync(offer.SessionId);
        await Clients.OthersInGroup(SessionGroupName(offer.SessionId))
            .SendAsync("ReceiveOffer", offer);
    }

    public async Task ForwardAnswer(AnswerDto answer)
    {
        await EnsureActiveMembershipAsync(answer.SessionId);
        await Clients.OthersInGroup(SessionGroupName(answer.SessionId))
            .SendAsync("ReceiveAnswer", answer);
    }

    public async Task ForwardIceCandidate(IceCandidateDto candidate)
    {
        await EnsureActiveMembershipAsync(candidate.SessionId);

        // Enforce relay-only media paths at the signalling boundary as well as endpoints.
        if (!TurnRelayConfiguration.IsCandidateAllowed(candidate.Candidate, IceTransportPolicy.RelayOnly))
        {
            throw new HubException("Non-relay ICE candidates are rejected by relay-only policy.");
        }

        await Clients.OthersInGroup(SessionGroupName(candidate.SessionId))
            .SendAsync("ReceiveIceCandidate", candidate);
    }

    public async Task<RelayVerificationResultDto> VerifySelectedCandidatePair(SelectedCandidatePairDto pair)
    {
        await EnsureActiveMembershipAsync(pair.SessionId);

        var verification = TurnRelayConfiguration.VerifySelectedCandidatePair(pair, IceTransportPolicy.RelayOnly);
        if (!verification.IsRelayVerified)
        {
            throw new HubException(verification.Reason);
        }

        return verification;
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        _tracker.RemoveConnection(Context.ConnectionId);
        return base.OnDisconnectedAsync(exception);
    }

    private async Task EnsureActiveMembershipAsync(Guid sessionId)
    {
        if (!_tracker.IsSessionMember(Context.ConnectionId, sessionId))
        {
            throw new HubException("Connection has not joined this session channel.");
        }

        var verification = await _authorizer.VerifyParticipantAsync(Context.User, sessionId, Context.ConnectionAborted);
        if (!verification.IsAuthorised)
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, SessionGroupName(sessionId));
            throw new HubException($"Session signalling rejected: {verification.FailureReason}");
        }
    }
}
