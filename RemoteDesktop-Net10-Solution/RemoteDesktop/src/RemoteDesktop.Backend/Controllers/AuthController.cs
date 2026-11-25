using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Contracts.Authentication;
using RemoteDesktop.Infrastructure.Persistence;
using RemoteDesktop.Security;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController : ControllerBase
{
    private static readonly SemaphoreSlim SetupLock = new(1, 1);

    private readonly ApplicationDbContext _db;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ITokenService _tokenService;

    public AuthController(
        ApplicationDbContext db,
        IPasswordHasher passwordHasher,
        ITokenService tokenService)
    {
        _db = db;
        _passwordHasher = passwordHasher;
        _tokenService = tokenService;
    }

    [HttpGet("status")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthStatusDto>> GetStatus(CancellationToken cancellationToken)
    {
        var envPasscodeSet = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ADMIN_PASSCODE"));
        var hasAdmin = await _db.Users.AnyAsync(u => u.Role == "Admin" && !u.IsDisabled, cancellationToken);
        return Ok(new AuthStatusDto(NeedsSetup: !envPasscodeSet && !hasAdmin, EnvPasscodeMode: envPasscodeSet));
    }

    [HttpPost("setup")]
    [AllowAnonymous]
    public async Task<ActionResult<LoginResponseDto>> SetupInitialAdmin(
        [FromBody] AdminSetupRequestDto request,
        CancellationToken cancellationToken)
    {
        var envPasscode = Environment.GetEnvironmentVariable("ADMIN_PASSCODE")?.Trim();
        if (!string.IsNullOrWhiteSpace(envPasscode))
            return Conflict(new { error = "Administrator passcode mode is active; interactive setup is disabled." });

        if (string.IsNullOrWhiteSpace(request.Email) || !request.Email.Contains('@') ||
            string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 8)
        {
            return BadRequest(new { error = "Valid email and password (minimum 8 characters) are required." });
        }

        await SetupLock.WaitAsync(cancellationToken);
        try
        {
            var hasAdmin = await _db.Users.AnyAsync(u => u.Role == "Admin", cancellationToken);
            if (hasAdmin)
                return Conflict(new { error = "Administrator account has already been configured." });

            var cleanEmail = request.Email.Trim().ToLowerInvariant();
            var user = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = cleanEmail,
                DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? "Primary Administrator" : request.DisplayName.Trim(),
                PasswordHash = _passwordHasher.HashPassword(request.Password),
                Role = "Admin",
                MfaEnabled = true,
                IsDisabled = false,
                CreatedAt = DateTimeOffset.UtcNow
            };

            _db.Users.Add(user);
            _db.AuditEvents.Add(new AuditEventEntity
            {
                Id = Guid.NewGuid(),
                EventType = "AdminClaimed",
                ActorUserId = user.Id,
                ActorEmail = user.Email,
                Summary = "Primary administrator account created during first-run setup.",
                OccurredAt = DateTimeOffset.UtcNow
            });
            await _db.SaveChangesAsync(cancellationToken);

            var (token, expiresAt, _) = _tokenService.IssueUserToken(user.Id, user.Email, user.Role);
            return Created(string.Empty, new LoginResponseDto(user.Id, user.Email, user.DisplayName, user.Role, token, expiresAt));
        }
        finally
        {
            SetupLock.Release();
        }
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<LoginResponseDto>> Login(
        [FromBody] LoginRequestDto request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { error = "Email and password are required." });

        var cleanEmail = request.Email.Trim().ToLowerInvariant();
        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var envPasscode = Environment.GetEnvironmentVariable("ADMIN_PASSCODE")?.Trim();

        if (!string.IsNullOrWhiteSpace(envPasscode))
        {
            var suppliedBytes = Encoding.UTF8.GetBytes(request.Password);
            var expectedBytes = Encoding.UTF8.GetBytes(envPasscode);
            if (CryptographicOperations.FixedTimeEquals(suppliedBytes, expectedBytes))
            {
                var admin = await _db.Users.FirstOrDefaultAsync(u => u.Email == cleanEmail && u.Role == "Admin", cancellationToken);
                if (admin is null)
                {
                    admin = new UserEntity
                    {
                        Id = Guid.NewGuid(),
                        Email = cleanEmail,
                        DisplayName = "Administrator",
                        PasswordHash = _passwordHasher.HashPassword(envPasscode),
                        Role = "Admin",
                        MfaEnabled = true,
                        CreatedAt = DateTimeOffset.UtcNow
                    };
                    _db.Users.Add(admin);
                }

                _db.AuthenticationEvents.Add(new AuthenticationEventEntity
                {
                    Id = Guid.NewGuid(),
                    SubjectType = "User",
                    SubjectIdentifier = cleanEmail,
                    Succeeded = true,
                    FailureReason = string.Empty,
                    RemoteIp = remoteIp,
                    OccurredAt = DateTimeOffset.UtcNow
                });
                await _db.SaveChangesAsync(cancellationToken);

                var (envToken, envExp, _) = _tokenService.IssueUserToken(admin.Id, admin.Email, admin.Role);
                return Ok(new LoginResponseDto(admin.Id, admin.Email, admin.DisplayName, admin.Role, envToken, envExp));
            }
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == cleanEmail, cancellationToken);
        if (user is null || user.IsDisabled || !_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
        {
            _db.AuthenticationEvents.Add(new AuthenticationEventEntity
            {
                Id = Guid.NewGuid(),
                SubjectType = "User",
                SubjectIdentifier = cleanEmail,
                Succeeded = false,
                FailureReason = "Invalid credentials or disabled account.",
                RemoteIp = remoteIp,
                OccurredAt = DateTimeOffset.UtcNow
            });
            _db.AuditEvents.Add(new AuditEventEntity
            {
                Id = Guid.NewGuid(),
                EventType = "AuthFailure",
                ActorEmail = cleanEmail,
                Summary = "Failed sign-in attempt rejected.",
                OccurredAt = DateTimeOffset.UtcNow
            });
            await _db.SaveChangesAsync(cancellationToken);
            return Unauthorized(new { error = "Invalid email or password." });
        }

        _db.AuthenticationEvents.Add(new AuthenticationEventEntity
        {
            Id = Guid.NewGuid(),
            SubjectType = "User",
            SubjectIdentifier = user.Email,
            Succeeded = true,
            FailureReason = string.Empty,
            RemoteIp = remoteIp,
            OccurredAt = DateTimeOffset.UtcNow
        });
        _db.AuditEvents.Add(new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "AuthSuccess",
            ActorUserId = user.Id,
            ActorEmail = user.Email,
            Summary = $"User signed in ({user.Role}).",
            OccurredAt = DateTimeOffset.UtcNow
        });
        await _db.SaveChangesAsync(cancellationToken);

        var (token, expiresAt, _) = _tokenService.IssueUserToken(user.Id, user.Email, user.Role);
        return Ok(new LoginResponseDto(user.Id, user.Email, user.DisplayName, user.Role, token, expiresAt));
    }
}
