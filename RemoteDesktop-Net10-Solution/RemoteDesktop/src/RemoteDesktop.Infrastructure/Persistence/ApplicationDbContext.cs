using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Contracts.Sessions;

namespace RemoteDesktop.Infrastructure.Persistence;

public sealed class UserEntity
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "Operator";
    public bool MfaEnabled { get; set; }
    public bool IsDisabled { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public UserMfaEntity? Mfa { get; set; }
    public ICollection<DevicePermissionEntity> Permissions { get; set; } = new List<DevicePermissionEntity>();
}

public sealed class UserMfaEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string ProtectedTotpSecret { get; set; } = string.Empty;
    public bool IsVerified { get; set; }
    public DateTimeOffset ConfiguredAt { get; set; }

    public UserEntity User { get; set; } = null!;
}

public sealed class DeviceEntity
{
    public Guid Id { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string OperatingSystem { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public DeviceStatus Status { get; set; }
    public bool IsApproved { get; set; }
    public bool IsRevoked { get; set; }
    public bool UnattendedAccessEnabled { get; set; }
    public int MonitorCount { get; set; } = 1;
    public bool SupportsWindowsGraphicsCapture { get; set; } = true;
    public bool SupportsDxgiDuplication { get; set; } = true;
    public string PreferredEncoder { get; set; } = "Software H.264 Fallback (OpenH264)";
    public bool SupportsHardwareEncoding { get; set; }
    public bool SupportsAudioCapture { get; set; } = true;
    public DateTimeOffset RegisteredAt { get; set; }
    public DateTimeOffset? LastOnlineAt { get; set; }

    public ICollection<DeviceKeyEntity> Keys { get; set; } = new List<DeviceKeyEntity>();
    public ICollection<DevicePermissionEntity> Permissions { get; set; } = new List<DevicePermissionEntity>();
    public ICollection<SessionEntity> HostSessions { get; set; } = new List<SessionEntity>();
}

public sealed class DeviceKeyEntity
{
    public Guid Id { get; set; }
    public Guid DeviceId { get; set; }
    public string PublicKeyBase64 { get; set; } = string.Empty;
    public string Fingerprint { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }

    public DeviceEntity Device { get; set; } = null!;
}

public sealed class EnrolmentTokenEntity
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public string TokenPreview { get; set; } = string.Empty;
    public Guid IssuedByUserId { get; set; }
    public string IssuedByEmail { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public Guid? UsedByDeviceId { get; set; }
}

public sealed class DevicePermissionEntity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid DeviceId { get; set; }
    public DevicePermission Permissions { get; set; }
    public bool AllowUnattendedAccess { get; set; }
    public DateTimeOffset GrantedAt { get; set; }

    public UserEntity User { get; set; } = null!;
    public DeviceEntity Device { get; set; } = null!;
}

public sealed class SessionEntity
{
    public Guid Id { get; set; }
    public Guid HostDeviceId { get; set; }
    public Guid ControllerUserId { get; set; }
    public Guid ControllerDeviceId { get; set; }
    public string ControllerDeviceName { get; set; } = string.Empty;
    public SessionState State { get; set; }
    public bool RelayOnlyEnforced { get; set; } = true;
    public string? SelectedCandidateType { get; set; }
    public string? SelectedRelayAddress { get; set; }
    public bool RequestUnattended { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ConnectedAt { get; set; }
    public DateTimeOffset? EndedAt { get; set; }
    public string? EndReason { get; set; }

    public DeviceEntity HostDevice { get; set; } = null!;
    public UserEntity ControllerUser { get; set; } = null!;
    public ICollection<SessionEventEntity> Events { get; set; } = new List<SessionEventEntity>();
}

public sealed class SessionEventEntity
{
    public Guid Id { get; set; }
    public Guid SessionId { get; set; }
    public SessionState PreviousState { get; set; }
    public SessionState NewState { get; set; }
    public string ActorIdentity { get; set; } = string.Empty;
    public string Note { get; set; } = string.Empty;
    public DateTimeOffset OccurredAt { get; set; }

    public SessionEntity Session { get; set; } = null!;
}

public sealed class AuditEventEntity
{
    public Guid Id { get; set; }
    public string EventType { get; set; } = string.Empty;
    public Guid? ActorUserId { get; set; }
    public string ActorEmail { get; set; } = string.Empty;
    public Guid? TargetDeviceId { get; set; }
    public Guid? SessionId { get; set; }
    public string Summary { get; set; } = string.Empty;
    public DateTimeOffset OccurredAt { get; set; }
}

public sealed class AuthenticationEventEntity
{
    public Guid Id { get; set; }
    public string SubjectType { get; set; } = string.Empty; // "User" | "Device"
    public string SubjectIdentifier { get; set; } = string.Empty;
    public bool Succeeded { get; set; }
    public string FailureReason { get; set; } = string.Empty;
    public string RemoteIp { get; set; } = string.Empty;
    public DateTimeOffset OccurredAt { get; set; }
}

public sealed class RevokedCredentialEntity
{
    public Guid Id { get; set; }
    public string CredentialJti { get; set; } = string.Empty;
    public Guid? DeviceId { get; set; }
    public Guid? UserId { get; set; }
    public string Reason { get; set; } = string.Empty;
    public DateTimeOffset RevokedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public sealed class DeploymentSettingEntity
{
    public int Id { get; set; } = 1;
    public string Environment { get; set; } = "Development";
    public string BackendBaseUrl { get; set; } = string.Empty;
    public string TurnHost { get; set; } = string.Empty;
    public int TurnPort { get; set; } = 3478;
    public string TurnTransport { get; set; } = "udp";
    public string TurnRealm { get; set; } = "remotedesktop.local";
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<UserMfaEntity> UserMfa => Set<UserMfaEntity>();
    public DbSet<DeviceEntity> Devices => Set<DeviceEntity>();
    public DbSet<DeviceKeyEntity> DeviceKeys => Set<DeviceKeyEntity>();
    public DbSet<EnrolmentTokenEntity> EnrolmentTokens => Set<EnrolmentTokenEntity>();
    public DbSet<DevicePermissionEntity> DevicePermissions => Set<DevicePermissionEntity>();
    public DbSet<SessionEntity> Sessions => Set<SessionEntity>();
    public DbSet<SessionEventEntity> SessionEvents => Set<SessionEventEntity>();
    public DbSet<AuditEventEntity> AuditEvents => Set<AuditEventEntity>();
    public DbSet<AuthenticationEventEntity> AuthenticationEvents => Set<AuthenticationEventEntity>();
    public DbSet<RevokedCredentialEntity> RevokedCredentials => Set<RevokedCredentialEntity>();
    public DbSet<DeploymentSettingEntity> DeploymentSettings => Set<DeploymentSettingEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<UserEntity>(e =>
        {
            e.ToTable("users");
            e.HasKey(x => x.Id);
            e.Property(x => x.Email).HasMaxLength(256).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(128).IsRequired();
            e.Property(x => x.PasswordHash).HasMaxLength(512).IsRequired();
            e.Property(x => x.Role).HasMaxLength(32).IsRequired();
            e.HasIndex(x => x.Email).IsUnique();
        });

        modelBuilder.Entity<UserMfaEntity>(e =>
        {
            e.ToTable("user_mfa");
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.UserId).IsUnique();
            e.HasOne(x => x.User)
                .WithOne(u => u.Mfa)
                .HasForeignKey<UserMfaEntity>(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<DeviceEntity>(e =>
        {
            e.ToTable("devices");
            e.HasKey(x => x.Id);
            e.Property(x => x.DisplayName).HasMaxLength(128).IsRequired();
            e.Property(x => x.OperatingSystem).HasMaxLength(128).IsRequired();
            e.Property(x => x.AppVersion).HasMaxLength(64).IsRequired();
            e.Property(x => x.PreferredEncoder).HasMaxLength(128).IsRequired();
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
        });

        modelBuilder.Entity<DeviceKeyEntity>(e =>
        {
            e.ToTable("device_keys");
            e.HasKey(x => x.Id);
            e.Property(x => x.PublicKeyBase64).HasMaxLength(1024).IsRequired();
            e.Property(x => x.Fingerprint).HasMaxLength(64).IsRequired();
            e.HasIndex(x => x.Fingerprint).IsUnique();
            e.HasOne(x => x.Device)
                .WithMany(d => d.Keys)
                .HasForeignKey(x => x.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<EnrolmentTokenEntity>(e =>
        {
            e.ToTable("enrolment_tokens");
            e.HasKey(x => x.Id);
            e.Property(x => x.TokenHash).HasMaxLength(128).IsRequired();
            e.Property(x => x.TokenPreview).HasMaxLength(32).IsRequired();
            e.Property(x => x.IssuedByEmail).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.TokenHash).IsUnique();
        });

        modelBuilder.Entity<DevicePermissionEntity>(e =>
        {
            e.ToTable("device_permissions");
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserId, x.DeviceId }).IsUnique();
            e.HasOne(x => x.User)
                .WithMany(u => u.Permissions)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Device)
                .WithMany(d => d.Permissions)
                .HasForeignKey(x => x.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SessionEntity>(e =>
        {
            e.ToTable("sessions");
            e.HasKey(x => x.Id);
            e.Property(x => x.ControllerDeviceName).HasMaxLength(128).IsRequired();
            e.Property(x => x.State).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.SelectedCandidateType).HasMaxLength(32);
            e.Property(x => x.SelectedRelayAddress).HasMaxLength(256);
            e.Property(x => x.EndReason).HasMaxLength(512);
            e.HasIndex(x => x.HostDeviceId);
            e.HasIndex(x => x.ControllerUserId);
            e.HasOne(x => x.HostDevice)
                .WithMany(d => d.HostSessions)
                .HasForeignKey(x => x.HostDeviceId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.ControllerUser)
                .WithMany()
                .HasForeignKey(x => x.ControllerUserId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<SessionEventEntity>(e =>
        {
            e.ToTable("session_events");
            e.HasKey(x => x.Id);
            e.Property(x => x.PreviousState).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.NewState).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.ActorIdentity).HasMaxLength(256).IsRequired();
            e.Property(x => x.Note).HasMaxLength(512).IsRequired();
            e.HasIndex(x => x.SessionId);
            e.HasOne(x => x.Session)
                .WithMany(s => s.Events)
                .HasForeignKey(x => x.SessionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuditEventEntity>(e =>
        {
            e.ToTable("audit_events");
            e.HasKey(x => x.Id);
            e.Property(x => x.EventType).HasMaxLength(64).IsRequired();
            e.Property(x => x.ActorEmail).HasMaxLength(256).IsRequired();
            e.Property(x => x.Summary).HasMaxLength(1024).IsRequired();
            e.HasIndex(x => x.OccurredAt);
        });

        modelBuilder.Entity<AuthenticationEventEntity>(e =>
        {
            e.ToTable("authentication_events");
            e.HasKey(x => x.Id);
            e.Property(x => x.SubjectType).HasMaxLength(32).IsRequired();
            e.Property(x => x.SubjectIdentifier).HasMaxLength(256).IsRequired();
            e.Property(x => x.FailureReason).HasMaxLength(512).IsRequired();
            e.Property(x => x.RemoteIp).HasMaxLength(64).IsRequired();
            e.HasIndex(x => x.OccurredAt);
        });

        modelBuilder.Entity<RevokedCredentialEntity>(e =>
        {
            e.ToTable("revoked_credentials");
            e.HasKey(x => x.Id);
            e.Property(x => x.CredentialJti).HasMaxLength(128).IsRequired();
            e.Property(x => x.Reason).HasMaxLength(512).IsRequired();
            e.HasIndex(x => x.CredentialJti).IsUnique();
            e.HasIndex(x => x.DeviceId);
        });

        modelBuilder.Entity<DeploymentSettingEntity>(e =>
        {
            e.ToTable("deployment_settings");
            e.HasKey(x => x.Id);
            e.Property(x => x.Environment).HasMaxLength(32).IsRequired();
            e.Property(x => x.BackendBaseUrl).HasMaxLength(256).IsRequired();
            e.Property(x => x.TurnHost).HasMaxLength(256).IsRequired();
            e.Property(x => x.TurnTransport).HasMaxLength(16).IsRequired();
            e.Property(x => x.TurnRealm).HasMaxLength(256).IsRequired();
        });
    }
}
