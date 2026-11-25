using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Configuration;
using RemoteDesktop.Backend.Hubs;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Infrastructure.Persistence;
using RemoteDesktop.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddControllers()
    .AddJsonOptions(opt => opt.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddSignalR()
    .AddJsonProtocol(opt => opt.PayloadSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

var securityOptions = new SecurityOptions();
builder.Configuration.GetSection("Security").Bind(securityOptions);
builder.Services.AddSingleton(securityOptions);

var signingKey = ServerSecretProvisioner.LoadOrProvisionSigningKey(
    builder.Configuration,
    builder.Environment.ContentRootPath);
var tokenService = new JwtTokenService(securityOptions, signingKey);
builder.Services.AddSingleton<ITokenService>(tokenService);

builder.Services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
builder.Services.AddSingleton<IDeviceIdentityService, DeviceIdentityService>();
builder.Services.AddSingleton<ISessionAuthorisationService, SessionAuthorisationService>();
builder.Services.AddSingleton<SignallingConnectionTracker>();
builder.Services.AddSingleton<IDeviceChallengeStore, InMemoryDeviceChallengeStore>();

builder.Services.AddScoped<ISessionParticipantAuthorizer, SessionParticipantAuthorizer>();
builder.Services.AddScoped<IEffectiveRelayService, EffectiveRelayService>();
builder.Services.AddScoped<ControlPlaneNotifier>();

var relayOptions = new RelayOptions();
builder.Configuration.GetSection("Relay").Bind(relayOptions);
relayOptions.Host = Environment.GetEnvironmentVariable("TURN_HOST") ?? relayOptions.Host;
relayOptions.Realm = Environment.GetEnvironmentVariable("TURN_REALM") ?? relayOptions.Realm;
relayOptions.SharedSecret = Environment.GetEnvironmentVariable("TURN_SHARED_SECRET") ?? relayOptions.SharedSecret;
if (int.TryParse(Environment.GetEnvironmentVariable("TURN_PORT"), out var envTurnPort))
{
    relayOptions.Port = envTurnPort;
}
relayOptions.RelayOnly = true;

var validation = StartupConfigurationValidator.Validate(builder.Configuration, builder.Environment, relayOptions);
foreach (var warning in validation.Warnings)
{
    Console.WriteLine($"[Config Warning] {warning}");
}
if (!validation.IsValid)
{
    foreach (var error in validation.Errors)
    {
        Console.Error.WriteLine($"[Config Error] {error}");
    }
    throw new InvalidOperationException("Required server configuration validation failed. Review errors above.");
}

builder.Services.AddSingleton(relayOptions);
builder.Services.AddSingleton(validation);
builder.Services.AddSingleton<ITurnCredentialProvider>(_ =>
    new TurnCredentialProvider(relayOptions.SharedSecret, relayOptions.BuildTurnUris()));

var useInMemory = builder.Configuration.GetValue("Testing:UseInMemoryDatabase", false);
if (!useInMemory)
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
        ?? Environment.GetEnvironmentVariable("REMOTEDESKTOP_DB")
        ?? throw new InvalidOperationException("Database connection string is required.");
    builder.Services.AddDbContext<ApplicationDbContext>(opt => opt.UseNpgsql(connectionString));
}

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = tokenService.CreateValidationParameters();
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs/signalling"))
                {
                    context.Token = accessToken;
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = async context =>
            {
                var db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
                var jti = context.Principal?.FindFirst("jti")?.Value;
                if (!string.IsNullOrWhiteSpace(jti))
                {
                    var revoked = await db.RevokedCredentials.AnyAsync(
                        r => r.CredentialJti == jti,
                        context.HttpContext.RequestAborted);
                    if (revoked)
                    {
                        context.Fail("Access token has been revoked.");
                        return;
                    }
                }

                var participantType = context.Principal?.FindFirst("participant_type")?.Value;
                if (string.Equals(participantType, "device", StringComparison.OrdinalIgnoreCase))
                {
                    var deviceIdStr = context.Principal?.FindFirst("device_id")?.Value;
                    if (!Guid.TryParse(deviceIdStr, out var deviceId))
                    {
                        context.Fail("Invalid device claim.");
                        return;
                    }

                    var device = await db.Devices.AsNoTracking()
                        .FirstOrDefaultAsync(d => d.Id == deviceId, context.HttpContext.RequestAborted);
                    if (device is null || device.IsRevoked || !device.IsApproved)
                    {
                        context.Fail("Device is revoked or no longer approved.");
                    }
                }
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireAuthenticatedUser()
            .RequireClaim("participant_type", "user")
            .RequireRole("Admin"));

    options.AddPolicy("UserAuthenticated", policy =>
        policy.RequireAuthenticatedUser()
            .RequireClaim("participant_type", "user"));

    options.AddPolicy("DeviceAuthenticated", policy =>
        policy.RequireAuthenticatedUser()
            .RequireClaim("participant_type", "device"));
});

var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
if (allowedOrigins.Length > 0)
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
            policy.WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials());
    });
}

var app = builder.Build();
app.UseForwardedHeaders();

if (allowedOrigins.Length > 0)
{
    app.UseCors();
}

if (!app.Environment.IsDevelopment() && builder.Configuration.GetValue("Server:UseHttpsRedirection", false))
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHub<SignallingHub>("/hubs/signalling");
app.Run();

public partial class Program;
