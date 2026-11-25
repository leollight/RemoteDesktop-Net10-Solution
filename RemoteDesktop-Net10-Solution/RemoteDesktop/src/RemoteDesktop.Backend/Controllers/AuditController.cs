using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Configuration;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Contracts.Authentication;
using RemoteDesktop.Contracts.Common;
using RemoteDesktop.Contracts.Configuration;
using RemoteDesktop.Contracts.Devices;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Infrastructure.Persistence;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api")]
[Authorize(Policy = "UserAuthenticated")]
public sealed class AuditController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IEffectiveRelayService _relayService;
    private readonly IHostEnvironment _environment;
    private readonly IConfiguration _configuration;

    public AuditController(
        ApplicationDbContext db,
        IEffectiveRelayService relayService,
        IHostEnvironment environment,
        IConfiguration configuration)
    {
        _db = db;
        _relayService = relayService;
        _environment = environment;
        _configuration = configuration;
    }

    [HttpGet("audit")]
    public async Task<ActionResult<IReadOnlyList<AuditEventDto>>> GetAuditEvents(CancellationToken cancellationToken)
    {
        var events = await _db.AuditEvents
            .OrderByDescending(e => e.OccurredAt)
            .Take(250)
            .ToListAsync(cancellationToken);

        return Ok(events.Select(EntityMappers.ToDto).ToList());
    }

    [HttpGet("overview")]
    public async Task<ActionResult<OverviewDto>> GetOverview(CancellationToken cancellationToken)
    {
        var users = await _db.Users
            .OrderBy(u => u.CreatedAt)
            .Select(u => new UserDto(u.Id, u.Email, u.DisplayName, u.Role, u.MfaEnabled, u.CreatedAt))
            .ToListAsync(cancellationToken);

        var devices = await _db.Devices
            .Include(d => d.Keys)
            .OrderByDescending(d => d.RegisteredAt)
            .ToListAsync(cancellationToken);

        var permissions = await _db.DevicePermissions
            .Select(p => new PermissionDto(p.Id, p.UserId, p.DeviceId, p.Permissions, p.AllowUnattendedAccess, p.GrantedAt))
            .ToListAsync(cancellationToken);

        var sessions = await _db.Sessions
            .OrderByDescending(s => s.CreatedAt)
            .Take(100)
            .ToListAsync(cancellationToken);

        var audit = await _db.AuditEvents
            .OrderByDescending(e => e.OccurredAt)
            .Take(250)
            .ToListAsync(cancellationToken);

        var now = DateTimeOffset.UtcNow;
        var activeTokens = await _db.EnrolmentTokens
            .Where(t => t.UsedAt == null && t.ExpiresAt > now)
            .OrderByDescending(t => t.CreatedAt)
            .Select(t => new EnrolmentTokenDto(t.Id, t.TokenPreview, t.IssuedByEmail, t.ExpiresAt, false))
            .ToListAsync(cancellationToken);

        var effectiveRelay = await _relayService.GetEffectiveOptionsAsync(cancellationToken);
        var hasAdmin = users.Any(u => u.Role == "Admin");
        var allowOptionalTurn = _environment.IsDevelopment()
            && _configuration.GetValue("Development:AllowUnconfiguredTurnForNonMediaStages", true);

        var relayDto = new RelaySettingsDto(
            _environment.EnvironmentName,
            effectiveRelay.PublicBaseUrl,
            effectiveRelay.Host,
            effectiveRelay.Port,
            effectiveRelay.Transport,
            effectiveRelay.Realm,
            RelayOnly: true);

        var validationDto = StartupConfigurationValidator.ToDto(
            _environment.EnvironmentName,
            hasAdmin,
            effectiveRelay,
            allowOptionalTurn);

        return Ok(new OverviewDto(
            users,
            devices.Select(d => EntityMappers.ToDto(d)).ToList(),
            permissions,
            sessions.Select(EntityMappers.ToDto).ToList(),
            audit.Select(EntityMappers.ToDto).ToList(),
            relayDto,
            validationDto,
            activeTokens));
    }
}
