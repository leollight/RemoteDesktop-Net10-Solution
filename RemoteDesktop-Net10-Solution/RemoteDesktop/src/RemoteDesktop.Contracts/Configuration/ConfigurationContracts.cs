using RemoteDesktop.Contracts.Common;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Sessions;

namespace RemoteDesktop.Contracts.Configuration;

public sealed record TurnEndpointDto(
    string Host,
    int Port,
    string Transport,
    string Realm);

public sealed record RuntimeConfigurationDto(
    string Environment,
    string BackendBaseUrl,
    string SignallingHubUrl,
    bool RelayOnly,
    bool TurnConfigured,
    TurnEndpointDto? Turn);

public sealed record RelaySettingsDto(
    string Environment,
    string BackendBaseUrl,
    string TurnHost,
    int TurnPort,
    string TurnTransport,
    string TurnRealm,
    bool RelayOnly);

public sealed record UpdateRelaySettingsDto(
    string Environment,
    string? BackendBaseUrl,
    string? TurnHost,
    int? TurnPort,
    string? TurnTransport,
    string? TurnRealm,
    bool LoadProfileDefaults = false);

public sealed record ConfigValidationDto(
    string Environment,
    bool Valid,
    bool AdminConfigured,
    bool SessionSecretProvisioned,
    bool TurnConfigured,
    string TurnStatus,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Errors);

public sealed record OverviewDto(
    IReadOnlyList<Authentication.UserDto> Users,
    IReadOnlyList<DeviceDto> Devices,
    IReadOnlyList<PermissionDto> Permissions,
    IReadOnlyList<SessionDto> Sessions,
    IReadOnlyList<AuditEventDto> AuditEvents,
    RelaySettingsDto RelayConfig,
    ConfigValidationDto ConfigValidation,
    IReadOnlyList<EnrolmentTokenDto> EnrolmentTokens);
