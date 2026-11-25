using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Configuration;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Contracts.Configuration;
using RemoteDesktop.Infrastructure.Persistence;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api/config")]
[Authorize]
public sealed class ConfigController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IHostEnvironment _environment;
    private readonly IConfiguration _configuration;
    private readonly IEffectiveRelayService _relayService;
    private readonly ControlPlaneNotifier _notifier;

    public ConfigController(
        ApplicationDbContext db,
        IHostEnvironment environment,
        IConfiguration configuration,
        IEffectiveRelayService relayService,
        ControlPlaneNotifier notifier)
    {
        _db = db;
        _environment = environment;
        _configuration = configuration;
        _relayService = relayService;
        _notifier = notifier;
    }

    [HttpGet("runtime")]
    public async Task<ActionResult<RuntimeConfigurationDto>> GetRuntimeConfiguration(CancellationToken cancellationToken)
    {
        var effective = await _relayService.GetEffectiveOptionsAsync(cancellationToken);
        var baseUrl = !string.IsNullOrWhiteSpace(effective.PublicBaseUrl)
            ? effective.PublicBaseUrl.TrimEnd('/')
            : $"{Request.Scheme}://{Request.Host}".TrimEnd('/');
        var hubUrl = $"{baseUrl}/hubs/signalling";

        TurnEndpointDto? turnEndpoint = effective.IsConfigured
            ? new TurnEndpointDto(
                effective.Host,
                effective.Port,
                effective.Transport,
                effective.Realm)
            : null;

        // Server-side TURN SharedSecret is never returned to Windows or browser clients.
        return Ok(new RuntimeConfigurationDto(
            Environment: _environment.EnvironmentName,
            BackendBaseUrl: baseUrl,
            SignallingHubUrl: hubUrl,
            RelayOnly: true,
            TurnConfigured: effective.IsConfigured,
            Turn: turnEndpoint));
    }

    [HttpPut("relay")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<object>> UpdateRelayConfiguration(
        [FromBody] UpdateRelaySettingsDto request,
        CancellationToken cancellationToken)
    {
        var setting = await _db.DeploymentSettings.FirstOrDefaultAsync(x => x.Id == 1, cancellationToken);
        if (setting is null)
        {
            setting = new DeploymentSettingEntity { Id = 1 };
            _db.DeploymentSettings.Add(setting);
        }

        var envName = request.Environment is "Production" or "Development"
            ? request.Environment
            : _environment.EnvironmentName;

        if (request.LoadProfileDefaults)
        {
            setting.Environment = envName;
            setting.TurnHost = string.Empty;
            setting.TurnPort = envName == "Production" ? 5349 : 3478;
            setting.TurnTransport = envName == "Production" ? "tls" : "udp";
            setting.TurnRealm = envName == "Production" ? "remotedesktop.example" : "remotedesktop.local";
        }
        else
        {
            setting.Environment = envName;
            if (request.BackendBaseUrl is not null)
                setting.BackendBaseUrl = request.BackendBaseUrl.Trim();
            if (request.TurnHost is not null)
                setting.TurnHost = request.TurnHost.Trim();
            if (request.TurnPort is > 0 and < 65536)
                setting.TurnPort = request.TurnPort.Value;
            if (request.TurnTransport is "udp" or "tcp" or "tls")
                setting.TurnTransport = request.TurnTransport;
            if (!string.IsNullOrWhiteSpace(request.TurnRealm))
                setting.TurnRealm = request.TurnRealm.Trim();
        }

        setting.UpdatedAt = DateTimeOffset.UtcNow;

        var actorEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? "admin";
        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "RelayConfigUpdated",
            ActorEmail = actorEmail,
            Summary = $"Updated relay profile ({setting.Environment}): Host={setting.TurnHost}, Port={setting.TurnPort}, Transport={setting.TurnTransport}.",
            OccurredAt = DateTimeOffset.UtcNow
        };
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);

        var effective = await _relayService.GetEffectiveOptionsAsync(cancellationToken);
        var hasAdmin = await _db.Users.AnyAsync(u => u.Role == "Admin" && !u.IsDisabled, cancellationToken);
        var allowOptionalTurn = _environment.IsDevelopment()
            && _configuration.GetValue("Development:AllowUnconfiguredTurnForNonMediaStages", true);

        return Ok(new
        {
            relayConfig = new RelaySettingsDto(
                setting.Environment,
                effective.PublicBaseUrl,
                effective.Host,
                effective.Port,
                effective.Transport,
                effective.Realm,
                RelayOnly: true),
            configValidation = StartupConfigurationValidator.ToDto(
                _environment.EnvironmentName,
                hasAdmin,
                effective,
                allowOptionalTurn)
        });
    }
}
