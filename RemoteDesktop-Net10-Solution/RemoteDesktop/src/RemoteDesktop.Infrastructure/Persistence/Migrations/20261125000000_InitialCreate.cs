using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteDesktop.Infrastructure.Persistence.Migrations
{
    [DbContext(typeof(ApplicationDbContext))]
    [Migration("20261125000000_InitialCreate")]
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_events",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EventType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ActorUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ActorEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TargetDeviceId = table.Column<Guid>(type: "uuid", nullable: true),
                    SessionId = table.Column<Guid>(type: "uuid", nullable: true),
                    Summary = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    OccurredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table => table.PrimaryKey("PK_audit_events", x => x.Id));

            migrationBuilder.CreateTable(
                name: "authentication_events",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SubjectType = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    SubjectIdentifier = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Succeeded = table.Column<bool>(type: "boolean", nullable: false),
                    FailureReason = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    RemoteIp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    OccurredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table => table.PrimaryKey("PK_authentication_events", x => x.Id));

            migrationBuilder.CreateTable(
                name: "deployment_settings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    Environment = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    BackendBaseUrl = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TurnHost = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TurnPort = table.Column<int>(type: "integer", nullable: false),
                    TurnTransport = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    TurnRealm = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table => table.PrimaryKey("PK_deployment_settings", x => x.Id));

            migrationBuilder.CreateTable(
                name: "devices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    OperatingSystem = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    AppVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    IsApproved = table.Column<bool>(type: "boolean", nullable: false),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    UnattendedAccessEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    MonitorCount = table.Column<int>(type: "integer", nullable: false),
                    SupportsWindowsGraphicsCapture = table.Column<bool>(type: "boolean", nullable: false),
                    SupportsDxgiDuplication = table.Column<bool>(type: "boolean", nullable: false),
                    PreferredEncoder = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SupportsHardwareEncoding = table.Column<bool>(type: "boolean", nullable: false),
                    SupportsAudioCapture = table.Column<bool>(type: "boolean", nullable: false),
                    RegisteredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastOnlineAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table => table.PrimaryKey("PK_devices", x => x.Id));

            migrationBuilder.CreateTable(
                name: "enrolment_tokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TokenHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    TokenPreview = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    IssuedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    IssuedByEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    UsedByDeviceId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table => table.PrimaryKey("PK_enrolment_tokens", x => x.Id));

            migrationBuilder.CreateTable(
                name: "revoked_credentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CredentialJti = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    DeviceId = table.Column<Guid>(type: "uuid", nullable: true),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table => table.PrimaryKey("PK_revoked_credentials", x => x.Id));

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    PasswordHash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    MfaEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsDisabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table => table.PrimaryKey("PK_users", x => x.Id));

            migrationBuilder.CreateTable(
                name: "device_keys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    PublicKeyBase64 = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Fingerprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_device_keys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_device_keys_devices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "device_permissions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    Permissions = table.Column<int>(type: "integer", nullable: false),
                    AllowUnattendedAccess = table.Column<bool>(type: "boolean", nullable: false),
                    GrantedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_device_permissions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_device_permissions_devices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_device_permissions_users_UserId",
                        column: x => x.UserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    HostDeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    ControllerUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    ControllerDeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    ControllerDeviceName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    State = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RelayOnlyEnforced = table.Column<bool>(type: "boolean", nullable: false),
                    SelectedCandidateType = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    SelectedRelayAddress = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    RequestUnattended = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ConnectedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    EndedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    EndReason = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_sessions_devices_HostDeviceId",
                        column: x => x.HostDeviceId,
                        principalTable: "devices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_sessions_users_ControllerUserId",
                        column: x => x.ControllerUserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "user_mfa",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProtectedTotpSecret = table.Column<string>(type: "text", nullable: false),
                    IsVerified = table.Column<bool>(type: "boolean", nullable: false),
                    ConfiguredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_mfa", x => x.Id);
                    table.ForeignKey(
                        name: "FK_user_mfa_users_UserId",
                        column: x => x.UserId,
                        principalTable: "users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "session_events",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SessionId = table.Column<Guid>(type: "uuid", nullable: false),
                    PreviousState = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    NewState = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ActorIdentity = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Note = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    OccurredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_session_events", x => x.Id);
                    table.ForeignKey(
                        name: "FK_session_events_sessions_SessionId",
                        column: x => x.SessionId,
                        principalTable: "sessions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(name: "IX_audit_events_OccurredAt", table: "audit_events", column: "OccurredAt");
            migrationBuilder.CreateIndex(name: "IX_authentication_events_OccurredAt", table: "authentication_events", column: "OccurredAt");
            migrationBuilder.CreateIndex(name: "IX_device_keys_DeviceId", table: "device_keys", column: "DeviceId");
            migrationBuilder.CreateIndex(name: "IX_device_keys_Fingerprint", table: "device_keys", column: "Fingerprint", unique: true);
            migrationBuilder.CreateIndex(name: "IX_device_permissions_DeviceId", table: "device_permissions", column: "DeviceId");
            migrationBuilder.CreateIndex(name: "IX_device_permissions_UserId_DeviceId", table: "device_permissions", columns: new[] { "UserId", "DeviceId" }, unique: true);
            migrationBuilder.CreateIndex(name: "IX_enrolment_tokens_TokenHash", table: "enrolment_tokens", column: "TokenHash", unique: true);
            migrationBuilder.CreateIndex(name: "IX_revoked_credentials_CredentialJti", table: "revoked_credentials", column: "CredentialJti", unique: true);
            migrationBuilder.CreateIndex(name: "IX_revoked_credentials_DeviceId", table: "revoked_credentials", column: "DeviceId");
            migrationBuilder.CreateIndex(name: "IX_session_events_SessionId", table: "session_events", column: "SessionId");
            migrationBuilder.CreateIndex(name: "IX_sessions_ControllerUserId", table: "sessions", column: "ControllerUserId");
            migrationBuilder.CreateIndex(name: "IX_sessions_HostDeviceId", table: "sessions", column: "HostDeviceId");
            migrationBuilder.CreateIndex(name: "IX_user_mfa_UserId", table: "user_mfa", column: "UserId", unique: true);
            migrationBuilder.CreateIndex(name: "IX_users_Email", table: "users", column: "Email", unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "audit_events");
            migrationBuilder.DropTable(name: "authentication_events");
            migrationBuilder.DropTable(name: "deployment_settings");
            migrationBuilder.DropTable(name: "device_keys");
            migrationBuilder.DropTable(name: "device_permissions");
            migrationBuilder.DropTable(name: "enrolment_tokens");
            migrationBuilder.DropTable(name: "revoked_credentials");
            migrationBuilder.DropTable(name: "session_events");
            migrationBuilder.DropTable(name: "user_mfa");
            migrationBuilder.DropTable(name: "sessions");
            migrationBuilder.DropTable(name: "devices");
            migrationBuilder.DropTable(name: "users");
        }
    }
}
