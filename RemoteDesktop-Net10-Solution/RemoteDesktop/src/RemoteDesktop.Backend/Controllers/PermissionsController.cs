using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteDesktop.Backend.Services;
using RemoteDesktop.Contracts.Permissions;
using RemoteDesktop.Infrastructure.Persistence;

namespace RemoteDesktop.Backend.Controllers;

[ApiController]
[Route("api/permissions")]
[Authorize(Policy = "UserAuthenticated")]
public sealed class PermissionsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly ControlPlaneNotifier _notifier;

    public PermissionsController(ApplicationDbContext db, ControlPlaneNotifier notifier)
    {
        _db = db;
        _notifier = notifier;
    }

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<PermissionDto>>> ListPermissions(CancellationToken cancellationToken)
    {
        var list = await _db.DevicePermissions
            .Select(p => new PermissionDto(p.Id, p.UserId, p.DeviceId, p.Permissions, p.AllowUnattendedAccess, p.GrantedAt))
            .ToListAsync(cancellationToken);
        return Ok(list);
    }

    [HttpPut]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<PermissionDto>> UpsertPermission(
        [FromBody] UpsertPermissionDto request,
        CancellationToken cancellationToken)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == request.UserId, cancellationToken);
        var device = await _db.Devices.FirstOrDefaultAsync(d => d.Id == request.DeviceId, cancellationToken);
        if (user is null || device is null)
            return NotFound(new { error = "User or target device not found." });

        var now = DateTimeOffset.UtcNow;
        var entity = await _db.DevicePermissions
            .FirstOrDefaultAsync(p => p.UserId == request.UserId && p.DeviceId == request.DeviceId, cancellationToken);

        if (entity is null)
        {
            entity = new DevicePermissionEntity
            {
                Id = Guid.NewGuid(),
                UserId = request.UserId,
                DeviceId = request.DeviceId,
                Permissions = request.Permissions,
                AllowUnattendedAccess = request.AllowUnattendedAccess,
                GrantedAt = now
            };
            _db.DevicePermissions.Add(entity);
        }
        else
        {
            entity.Permissions = request.Permissions;
            entity.AllowUnattendedAccess = request.AllowUnattendedAccess;
            entity.GrantedAt = now;
        }

        var actorEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? "admin";
        var audit = new AuditEventEntity
        {
            Id = Guid.NewGuid(),
            EventType = "PermissionUpdated",
            ActorEmail = actorEmail,
            TargetDeviceId = device.Id,
            Summary = $"Updated permissions for {user.Email} on {device.DisplayName}: {request.Permissions}.",
            OccurredAt = now
        };
        _db.AuditEvents.Add(audit);
        await _db.SaveChangesAsync(cancellationToken);

        var dto = new PermissionDto(entity.Id, entity.UserId, entity.DeviceId, entity.Permissions, entity.AllowUnattendedAccess, entity.GrantedAt);
        await _notifier.NotifyPermissionUpdatedAsync(dto, cancellationToken);
        await _notifier.NotifyAuditCreatedAsync(EntityMappers.ToDto(audit), cancellationToken);
        return Ok(dto);
    }
}
