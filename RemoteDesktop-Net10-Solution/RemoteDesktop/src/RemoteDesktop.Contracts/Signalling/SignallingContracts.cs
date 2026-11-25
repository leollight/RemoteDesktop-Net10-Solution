namespace RemoteDesktop.Contracts.Signalling;

public sealed record OfferDto(Guid SessionId, string Sdp);

public sealed record AnswerDto(Guid SessionId, string Sdp);

public sealed record IceCandidateDto(
    Guid SessionId,
    string Candidate,
    string SdpMid,
    int SdpMLineIndex,
    string CandidateType);

public sealed record SelectedCandidatePairDto(
    Guid SessionId,
    string LocalCandidateType,
    string RemoteCandidateType,
    string TransportProtocol,
    string RelayServerAddress,
    string PairState);

public sealed record RelayVerificationResultDto(
    bool IsRelayVerified,
    string Reason);

public sealed record SignallingMessage(
    Guid SessionId,
    string MessageType,
    string Payload,
    DateTimeOffset SentAt);
