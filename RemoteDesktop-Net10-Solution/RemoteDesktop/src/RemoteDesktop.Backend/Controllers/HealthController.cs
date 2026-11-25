using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Configuration;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Infrastructure.Persistence;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api/health")]
[AllowAnonymous]
public sealed class HealthController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IEffectiveRelayService _relayService;
    private readonly IHostEnvironment _environment;
    private readonly IConfiguration _configuration;

    public HealthController(
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

    [HttpGet]
    public async Task<IActionResult> GetHealth(CancellationToken cancellationToken)
    {
        var effectiveRelay = await _relayService.GetEffectiveOptionsAsync(cancellationToken);
        var hasAdmin = await _db.Users.AnyAsync(u => u.Role == "Admin" && !u.IsDisabled, cancellationToken);
        var allowOptionalTurn = _environment.IsDevelopment()
            && _configuration.GetValue("Development:AllowUnconfiguredTurnForNonMediaStages", true);

        var validation = StartupConfigurationValidator.ToDto(
            _environment.EnvironmentName,
            hasAdmin,
            effectiveRelay,
            allowOptionalTurn);

        return Ok(new
        {
            status = validation.Valid ? "ok" : "degraded",
            service = "RemoteDesktop.Backend",
            environment = validation.Environment,
            relayOnly = true,
            turnConfigured = validation.TurnConfigured,
            turnStatus = validation.TurnStatus,
            warnings = validation.Warnings,
            errors = validation.Errors
        });
    }
}
