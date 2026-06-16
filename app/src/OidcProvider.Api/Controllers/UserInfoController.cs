using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Controllers;

// OIDC Core §5.3. The access token (Bearer or DPoP-bound) is validated by the OpenIddict
// validation handler before this runs; an expired/invalid/revoked token yields 401
// invalid_token automatically (threat T3 / tests AC-T3-1). `sub` MUST equal the id_token's
// pairwise sub for this client (ADR-0010).
[ApiController]
public sealed class UserInfoController : Controller
{
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("/userinfo"), HttpPost("/userinfo"), Produces("application/json")]
    public IActionResult UserInfo()
    {
        var claims = new Dictionary<string, object>
        {
            [Claims.Subject] = User.GetClaim(Claims.Subject)!  // pairwise PPID
        };

        if (User.HasScope(Scopes.Email))
        {
            if (User.GetClaim(Claims.Email) is { } email) claims[Claims.Email] = email;
            if (User.GetClaim(Claims.EmailVerified) is { } ev)
                claims[Claims.EmailVerified] = bool.TryParse(ev, out var b) && b;
        }
        if (User.HasScope(Scopes.Profile) && User.GetClaim(Claims.Name) is { } name)
            claims[Claims.Name] = name;

        return Ok(claims);
    }
}
