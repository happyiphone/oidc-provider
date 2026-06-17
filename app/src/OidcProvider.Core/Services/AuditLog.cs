using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OidcProvider.Core.Data;
using OidcProvider.Core.Entities;

namespace OidcProvider.Core.Services;

// Tamper-evident audit log (threat T16). Each row links to the previous via a hash chain:
// row_hash = SHA256(prev_hash || payload). The app only ever INSERTs (no update/delete),
// so a deleted or altered row breaks the chain and is detectable on replay.
// NOTE: the chain is best-effort under high concurrency (a strict total order would need a
// serialized writer / DB sequence lock); adequate for tamper-evidence in this reference.
public interface IAuditLog
{
    Task WriteAsync(string eventType, Guid? actorUser = null, string? clientId = null,
        object? detail = null, CancellationToken ct = default);
}

public sealed class EfAuditLog : IAuditLog
{
    private readonly AuthDbContext _db;
    public EfAuditLog(AuthDbContext db) => _db = db;

    public async Task WriteAsync(string eventType, Guid? actorUser = null, string? clientId = null,
        object? detail = null, CancellationToken ct = default)
    {
        var detailJson = detail is null ? "{}" : JsonSerializer.Serialize(detail);
        var occurredAt = DateTimeOffset.UtcNow;
        var prev = await _db.AuditLog.OrderByDescending(a => a.Id)
            .Select(a => a.RowHash).FirstOrDefaultAsync(ct);

        var payload = Encoding.UTF8.GetBytes(
            $"{eventType}|{actorUser}|{clientId}|{detailJson}|{occurredAt:O}");
        var rowHash = SHA256.HashData([.. prev ?? [], .. payload]);

        _db.AuditLog.Add(new AuditEntry
        {
            OccurredAt = occurredAt,
            ActorUser = actorUser,
            ClientId = clientId,
            EventType = eventType,
            DetailJson = detailJson,
            PrevHash = prev,
            RowHash = rowHash,
        });
        await _db.SaveChangesAsync(ct);
    }
}
