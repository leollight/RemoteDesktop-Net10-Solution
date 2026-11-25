namespace RemoteDesktop.Contracts.Common;

public sealed record ErrorDto(string Code, string Message);

public sealed record ApiResponse<T>(bool Success, T? Data, ErrorDto? Error);

public sealed record AuditEventDto(
    Guid Id,
    string EventType,
    string ActorEmail,
    Guid? TargetDeviceId,
    Guid? SessionId,
    string Summary,
    DateTimeOffset OccurredAt);
