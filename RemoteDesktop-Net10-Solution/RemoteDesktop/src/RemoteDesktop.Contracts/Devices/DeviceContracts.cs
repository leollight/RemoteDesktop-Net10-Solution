namespace RemoteDesktop.Contracts.Devices;

public sealed record DeviceDto(
    Guid Id,
    string DisplayName,
    string OperatingSystem,
    string AppVersion,
    string PublicKeyFingerprint,
    DeviceStatus Status,
    bool IsApproved,
    bool IsRevoked,
    bool UnattendedAccessEnabled,
    DateTimeOffset RegisteredAt,
    DateTimeOffset? LastOnlineAt,
    DeviceCapabilitiesDto Capabilities);

public sealed record DeviceRegistrationDto(
    string DisplayName,
    string OperatingSystem,
    string AppVersion,
    string PublicKeyBase64,
    string EnrolmentToken,
    DeviceCapabilitiesDto Capabilities);

public sealed record EnrolmentTokenDto(
    Guid Id,
    string Token,
    string IssuedByEmail,
    DateTimeOffset ExpiresAt,
    bool Used);

public sealed record ToggleUnattendedDto(bool Enabled);

public sealed record UpdateDeviceStatusDto(DeviceStatus Status);

public enum DeviceStatus
{
    PendingApproval = 0,
    Offline = 1,
    Online = 2,
    InSession = 3,
    Revoked = 4
}

public sealed record DeviceStatusDto(
    Guid DeviceId,
    DeviceStatus Status,
    DateTimeOffset ObservedAt);

public sealed record DeviceCapabilitiesDto(
    int MonitorCount,
    bool SupportsWindowsGraphicsCapture,
    bool SupportsDxgiDuplication,
    string PreferredEncoder,
    bool SupportsHardwareEncoding,
    bool SupportsAudioCapture);
