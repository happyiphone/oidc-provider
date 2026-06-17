using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OidcProvider.Core.Services;
using OpenIddict.Server.AspNetCore;

namespace OidcProvider.Api.Controllers;

// RP-initiated logout (OIDC end-session). OpenIddict validates id_token_hint and the
// post_logout_redirect_uri against the client's registered set; we terminate the local
// session, then SignOut on the OpenIddict scheme produces the redirect back to the RP.
// (A production UI should show a logout-confirmation prompt; omitted here for brevity.)
public sealed class LogoutController : Controller
{
    private readonly IUserSession _sessions;
    private readonly IAuditLog _audit;
    public LogoutController(IUserSession sessions, IAuditLog audit) => (_sessions, _audit) = (sessions, audit);

    [HttpGet("/logout"), HttpPost("/logout"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        if (User.FindFirst("sid")?.Value is { } sid)
        {
            await _sessions.RevokeAsync(sid);                                  // kill the Redis session
            await _audit.WriteAsync("logout",
                User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value is { } u
                    ? Guid.Parse(u) : null);
        }
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); // clear the cookie

        // OpenIddict emits the post_logout_redirect_uri redirect (validated against the
        // client's registered URIs); RedirectUri is the fallback when none was supplied.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }
}
