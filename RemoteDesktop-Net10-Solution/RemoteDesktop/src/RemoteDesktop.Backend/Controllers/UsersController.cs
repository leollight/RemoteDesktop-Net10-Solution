using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Contracts.Authentication;
using RemoteDesktop.Infrastructure.Persistence;
using RemoteDesktop.Security;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api/users")]
[Authorize(Policy = "AdminOnly")]
public sealed class UsersController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ControlPlaneNotifier _notifier;

    public UsersController(
        ApplicationDbContext db,
        IPasswordHasher passwordHasher,
        ControlPlaneNotifier notifier)
    {
        _db = db;
        _passwordHasher = passwordHasher;
        _notifier = notifier;
    }

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<UserDto>>> ListUsers(CancellationToken cancellationToken)
    {
        var users = await _db.Users
            .OrderBy(u => u.CreatedAt)
            .Select(u => new UserDto(u.Id, u.Email, u.DisplayName, u.Role, u.MfaEnabled, u.CreatedAt))
            .ToListAsync(cancellationToken);
        return Ok(users);
    }

    [HttpPost]
    public async Task<ActionResult<UserDto>> CreateUser(
        [FromBody] CreateUserRequestDto request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || !request.Email.Contains('@')
            || string.IsNullOrWhiteSpace(request.DisplayName)
            || string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 8)
        {
            return BadRequest(new { error = "Valid email, displayName, and password (8+ chars) are required." });
        }

        var cleanEmail = request.Email.Trim().ToLowerInvariant();
        if (await _db.Users.AnyAsync(u => u.Email == cleanEmail, cancellationToken))
            return Conflict(new { error = "A user with this email already exists." });

        var role = request.Role is "Admin" or "Operator" or "Viewer" ? request.Role : "Operator";
        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            Email = cleanEmail,
            DisplayName = request.DisplayName.Trim(),
            PasswordHash = _passwordHasher.HashPassword(request.Password),
            Role = role,
            MfaEnabled = true,
            IsDisabled = false,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var actorEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? "admin";
        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "UserCreated",
            ActorEmail = actorEmail,
            Summary = $"Created {role} account for {cleanEmail}.",
            OccurredAt = DateTimeOffset.UtcNow
        };

        _db.Users.Add(user);
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);

        return Created(string.Empty, new UserDto(user.Id, user.Email, user.DisplayName, user.Role, user.MfaEnabled, user.CreatedAt));
    }
}
