using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OidcProvider.Core;
using OidcProvider.Core.Data;
using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using StackExchange.Redis;

namespace OidcProvider.Api.Controllers;

// Shared CIBA constants + the pending-request record (poll mode).
public static class Ciba
{
    public const string GrantType = "urn:openid:params:grant-type:ciba";
    public static string Key(string id) => $"ciba:{id}";
}
public sealed record CibaRequest(Guid UserId, string ClientId, string Scope, string Status); // pending|approved|denied

// OpenID Connect Client-Initiated Backchannel Authentication (CIBA), poll mode. OpenIddict has no
// native CIBA, so we own the backchannel-authentication + approval endpoints here and register the
// grant as a custom flow; the TOKEN side still mints via OpenIddict (SignIn) so token management,
// signing, and refresh handling are unchanged. Decoupled auth is modelled as a separate approval
// endpoint the user hits on their authenticated device.
[ApiController]
public sealed class CibaController : Controller
{
    private readonly IDatabase _redis;
    private readonly IOpenIddictApplicationManager _apps;
    private readonly AuthDbContext _db;
    private readonly IUserSession _sessions;
    private readonly IAuditLog _audit;
    public CibaController(IConnectionMultiplexer mux, IOpenIddictApplicationManager apps,
        AuthDbContext db, IUserSession sessions, IAuditLog audit)
        => (_redis, _apps, _db, _sessions, _audit) = (mux.GetDatabase(), apps, db, sessions, audit);

    // Device/client starts the flow (RFC: backchannel_authentication_endpoint).
    [HttpPost("/ciba"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Initiate(
        [FromForm] string? client_id, [FromForm] string? client_secret,
        [FromForm] string? scope, [FromForm] string? login_hint)
    {
        var app = client_id is null ? null : await _apps.FindByClientIdAsync(client_id);
        if (app is null || !await _apps.ValidateClientSecretAsync(app, client_secret ?? ""))
            return Unauthorized(new { error = "invalid_client" });

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == login_hint);
        if (user is null) return BadRequest(new { error = "unknown_user_id", error_description = "Unknown login_hint." });

        var authReqId = Base64UrlText.Encode(RandomNumberGenerator.GetBytes(32)); // unguessable
        var rec = new CibaRequest(user.Id, client_id!, string.IsNullOrWhiteSpace(scope) ? "openid" : scope!, "pending");
        await _redis.StringSetAsync(Ciba.Key(authReqId), JsonSerializer.Serialize(rec), TimeSpan.FromMinutes(5));
        await _audit.WriteAsync("ciba.initiated", user.Id, client_id);

        // RFC 8628-style polling response.
        return Ok(new { auth_req_id = authReqId, expires_in = 300, interval = 2 });
    }

    // The user approves (or denies) on their authenticated device (decoupled from the client).
    [HttpPost("/ciba/approve"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Approve([FromForm] string? auth_req_id, [FromForm] string? decision)
    {
        var sid = User.FindFirst("sid")?.Value;
        var session = sid is null ? null : await _sessions.GetAsync(sid);
        if (session is null) return Unauthorized(new { error = "login_required" });

        var raw = await _redis.StringGetAsync(Ciba.Key(auth_req_id ?? ""));
        if (raw.IsNullOrEmpty) return NotFound(new { error = "expired_token" });
        var rec = JsonSerializer.Deserialize<CibaRequest>(raw!)!;
        if (rec.UserId != session.UserId) return Forbid(); // only the hinted user may approve

        var updated = rec with { Status = decision == "approve" ? "approved" : "denied" };
        await _redis.StringSetAsync(Ciba.Key(auth_req_id!), JsonSerializer.Serialize(updated), TimeSpan.FromMinutes(5));
        await _audit.WriteAsync($"ciba.{updated.Status}", session.UserId, rec.ClientId);
        return Ok(new { status = updated.Status });
    }
}
