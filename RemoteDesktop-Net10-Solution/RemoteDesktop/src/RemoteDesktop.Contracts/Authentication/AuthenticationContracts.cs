namespace RemoteDesktop.Contracts.Authentication;

public sealed record AuthStatusDto(
    bool NeedsSetup,
    bool EnvPasscodeMode);

public sealed record AdminSetupRequestDto(
    string Email,
    string DisplayName,
    string Password);

public sealed record LoginRequestDto(
    string Email,
    string Password,
    string? MfaCode);

public sealed record UserDto(
    Guid Id,
    string Email,
    string DisplayName,
    string Role,
    bool MfaEnabled,
    DateTimeOffset CreatedAt);

public sealed record CreateUserRequestDto(
    string Email,
    string DisplayName,
    string Role,
    string Password);

public sealed record LoginResponseDto(
    Guid UserId,
    string Email,
    string DisplayName,
    string Role,
    string AccessToken,
    DateTimeOffset ExpiresAt);

public sealed record DeviceChallengeRequestDto(Guid DeviceId);

public sealed record DeviceChallengeDto(
    Guid DeviceId,
    string NonceBase64,
    DateTimeOffset ExpiresAt);

public sealed record DeviceChallengeResponseDto(
    Guid DeviceId,
    string NonceBase64,
    string SignatureBase64);

public sealed record DeviceAuthResponseDto(
    Guid DeviceId,
    bool IsApproved,
    bool IsRevoked,
    string AccessToken,
    DateTimeOffset ExpiresAt);
