using System.Net;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace OidcProvider.Api.Controllers;

// RP-initiated logout (OIDC end-session). OpenIddict validates id_token_hint and the
// post_logout_redirect_uri against the client's registered set; we terminate the local session,
// fan out BOTH logout channels, then redirect back to the RP.
//   • Back-channel (BCL 1.0): server-to-server signed logout_token to each RP — robust, the default.
//   • Front-channel (FCL 1.0): hidden <iframe> per RP at end-session — best-effort, here as a
//     complement (it can be blocked by third-party-cookie rules; sid in the URL lets the RP target
//     the exact session regardless of cookies).
public sealed class LogoutController : Controller
{
    private readonly IUserSession _sessions;
    private readonly IAuditLog _audit;
    private readonly IBackChannelLogoutNotifier _bcl;
    private readonly IOpenIddictApplicationManager _apps;
    private readonly IConfiguration _cfg;
    public LogoutController(IUserSession sessions, IAuditLog audit, IBackChannelLogoutNotifier bcl,
        IOpenIddictApplicationManager apps, IConfiguration cfg)
        => (_sessions, _audit, _bcl, _apps, _cfg) = (sessions, audit, bcl, apps, cfg);

    [HttpGet("/logout"), HttpPost("/logout"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        var frontChannel = new List<string>();

        if (User.FindFirst("sid")?.Value is { } sid)
        {
            // Snapshot the session's RPs BEFORE revoking, then notify both channels.
            var clients = await _sessions.GetClientsAsync(sid);
            if (await _sessions.GetAsync(sid) is { } s && clients.Count > 0)
                await _bcl.NotifyAsync(s.UserId, sid, clients);

            // Collect front-channel logout URIs (with iss+sid per FCL §3) for the iframe page.
            var issuer = _cfg["Oidc:Issuer"] ?? "";
            foreach (var clientId in clients)
            {
                var app = await _apps.FindByClientIdAsync(clientId);
                if (app is null) continue;
                var props = await _apps.GetPropertiesAsync(app);
                if (props.TryGetValue("frontchannel_logout_uri", out var fu) &&
                    fu.GetString() is { Length: > 0 } uri)
                {
                    var sep = uri.Contains('?') ? '&' : '?';
                    frontChannel.Add($"{uri}{sep}iss={Uri.EscapeDataString(issuer)}&sid={Uri.EscapeDataString(sid)}");
                }
            }

            await _sessions.RevokeAsync(sid);                                  // kill the Redis session
            await _audit.WriteAsync("logout",
                User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value is { } u
                    ? Guid.Parse(u) : null);
        }
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); // clear the cookie

        // If any RP registered a front-channel logout URI, render the iframe page ourselves (it
        // loads each RP's logout in a hidden frame) and then bounce to the post-logout redirect.
        if (frontChannel.Count > 0)
        {
            var dest = request?.PostLogoutRedirectUri is { Length: > 0 } d ? d : "/";
            var sb = new StringBuilder("<!doctype html><meta charset=utf-8><title>Signing out…</title>");
            foreach (var f in frontChannel)
                sb.Append($"<iframe src=\"{WebUtility.HtmlEncode(f)}\" style=\"display:none\" sandbox=\"allow-same-origin allow-scripts\"></iframe>");
            sb.Append($"<p>Signing you out…</p><script>setTimeout(function(){{location.href={System.Text.Json.JsonSerializer.Serialize(dest)};}},1500);</script>");
            return Content(sb.ToString(), "text/html");
        }

        // No front-channel RPs → let OpenIddict emit the validated post_logout_redirect_uri redirect.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }
}
