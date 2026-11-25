using RemoteDesktop.Contracts.Sessions;
using RemoteDesktop.Contracts.Signalling;
using RemoteDesktop.Media;

namespace RemoteDesktop.Controller.Services;

public sealed class SessionClient
{
    public bool ValidateSelectedCandidate(IceTransportPolicy policy, string selectedCandidateLine)
    {
        if (!TurnRelayConfiguration.IsCandidateAllowed(selectedCandidateLine, policy))
        {
            throw new InvalidOperationException("Session aborted: relay-only policy rejected non-relayed ICE candidate.");
        }
        return true;
    }

    public RelayVerificationResultDto VerifyCandidatePair(SelectedCandidatePairDto pair)
    {
        var result = TurnRelayConfiguration.VerifySelectedCandidatePair(pair, IceTransportPolicy.RelayOnly);
        if (!result.IsRelayVerified)
        {
            throw new InvalidOperationException($"Session aborted: {result.Reason}");
        }
        return result;
    }

    public bool CanRequestTransition(SessionState current, SessionState target) =>
        SessionStateTransitions.CanTransition(current, target);
}
