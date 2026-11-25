namespace RemoteDesktop.Contracts.Permissions;

[Flags]
public enum DevicePermission
{
    None = 0,
    ViewScreen = 1 << 0,
    ControlMouse = 1 << 1,
    ControlKeyboard = 1 << 2,
    AudioAccess = 1 << 3,
    ClipboardAccess = 1 << 4,
    FileTransfer = 1 << 5,
    DeviceManage = 1 << 6,
    SessionManage = 1 << 7
}

public sealed record PermissionDto(
    Guid Id,
    Guid UserId,
    Guid DeviceId,
    DevicePermission Permissions,
    bool AllowUnattendedAccess,
    DateTimeOffset GrantedAt);

public sealed record UpsertPermissionDto(
    Guid UserId,
    Guid DeviceId,
    DevicePermission Permissions,
    bool AllowUnattendedAccess);
