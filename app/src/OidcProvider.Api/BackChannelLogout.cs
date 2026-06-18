using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OidcProvider.Core.Data;
using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace OidcProvider.Api;

// OpenID Connect Back-Channel Logout 1.0. OpenIddict (≤6.x) has no first-class server support,
// so we own it: when a session ends, mint a signed `logout_token` for every RP that
// authenticated under it (and registered a `backchannel_logout_uri`) and POST it server-to-server.
public interface IBackChannelLogoutNotifier
{
    Task NotifyAsync(Guid userId, string sid, IEnumerable<string> clientIds, CancellationToken ct = default);
    // Fan out across every session of a user (credential change / "log out everywhere"). Each RP
    // gets a logout_token bound to the specific sid it joined.
    Task NotifyAllSessionsAsync(Guid userId, IReadOnlyDictionary<string, string[]> sessionClients,
        CancellationToken ct = default);
}

public sealed class BackChannelLogoutNotifier : IBackChannelLogoutNotifier
{
    // The single member that marks a JWT as a back-channel logout event (spec §2.4).
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private readonly IOpenIddictApplicationManager _apps;
    private readonly IPairwiseSubjects _ppid;
    private readonly AuthDbContext _db;
    // MUST be the monitor (not IOptions): OpenIddict reads its options through IOptionsMonitor, and
    // the Dev signing key is created inside Configure(). Resolving via IOptions would run Configure
    // against a different cache → a second EC key with the SAME kid but different material →
    // logout_token signatures that fail at the RP. The monitor shares OpenIddict's exact key.
    private readonly IOptionsMonitor<OpenIddictServerOptions> _server;
    private readonly IHttpClientFactory _http;
    private readonly IConfiguration _cfg;
    private readonly ILogger<BackChannelLogoutNotifier> _log;

    public BackChannelLogoutNotifier(IOpenIddictApplicationManager apps, IPairwiseSubjects ppid,
        AuthDbContext db, IOptionsMonitor<OpenIddictServerOptions> server, IHttpClientFactory http,
        IConfiguration cfg, ILogger<BackChannelLogoutNotifier> log)
        => (_apps, _ppid, _db, _server, _http, _cfg, _log)
           = (apps, ppid, db, server, http, cfg, log);

    public async Task NotifyAsync(Guid userId, string sid, IEnumerable<string> clientIds, CancellationToken ct = default)
    {
        // Must match the OP's canonical issuer EXACTLY (trailing slash included) — the RP validates
        // logout_token `iss` against the issuer it discovered, same as for id_tokens.
        var issuer = _cfg["Oidc:Issuer"] ?? "";
        var creds = _server.CurrentValue.SigningCredentials.FirstOrDefault()
            ?? throw new InvalidOperationException("No signing credentials available for logout_token.");
        var client = _http.CreateClient("backchannel-logout");

        foreach (var clientId in clientIds.Distinct())
        {
            var app = await _apps.FindByClientIdAsync(clientId, ct);
            if (app is null) continue;
            var props = await _apps.GetPropertiesAsync(app, ct);
            if (!props.TryGetValue("backchannel_logout_uri", out var uriProp) ||
                uriProp.GetString() is not { Length: > 0 } uri)
                continue; // RP didn't opt in

            // sub must equal the pairwise subject this RP originally received.
            var sector = (await _db.ClientPolicies.FindAsync([clientId], ct))?.SectorIdentifier ?? clientId;
            var sub = await _ppid.ForAsync(userId, sector);

            var token = BuildLogoutToken(issuer, clientId, sub, sid, creds);
            try
            {
                using var body = new FormUrlEncodedContent(
                    new[] { new KeyValuePair<string, string>("logout_token", token) });
                var resp = await client.PostAsync(uri, body, ct);
                _log.LogInformation("Back-channel logout → {ClientId} {Uri}: {Status}",
                    clientId, uri, (int)resp.StatusCode);
            }
            catch (Exception ex)
            {
                // An unreachable/erroring RP must not break the user's logout (spec is best-effort).
                _log.LogWarning(ex, "Back-channel logout to {ClientId} {Uri} failed", clientId, uri);
            }
        }
    }

    public async Task NotifyAllSessionsAsync(Guid userId, IReadOnlyDictionary<string, string[]> sessionClients,
        CancellationToken ct = default)
    {
        foreach (var (sid, clients) in sessionClients)
            await NotifyAsync(userId, sid, clients, ct);
    }

    private static string BuildLogoutToken(string issuer, string aud, string sub, string sid,
        SigningCredentials creds)
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = aud,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.AddMinutes(2).UtcDateTime, // short-lived; consumed immediately
            SigningCredentials = creds,
            // typ=logout+jwt distinguishes it from an id_token at the RP (spec §2.4).
            AdditionalHeaderClaims = new Dictionary<string, object> { ["typ"] = "logout+jwt" },
            Claims = new Dictionary<string, object>
            {
                ["sub"] = sub,
                ["sid"] = sid,
                ["jti"] = Guid.NewGuid().ToString("N"),
                // events: { "<logout-event-uri>": {} } — REQUIRED, and the absence of `nonce`
                // is what forbids reusing this as an id_token.
                ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
            },
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}
