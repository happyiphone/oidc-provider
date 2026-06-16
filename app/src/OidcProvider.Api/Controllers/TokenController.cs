using System.Security.Claims;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest extension
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OidcProvider.Core.Signing;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Controllers;

// Token endpoint passthrough. OpenIddict performs client auth, code single-use +
// redirect_uri + PKCE checks, and refresh-token validation/rolling BEFORE this runs.
// Our job: rebuild the principal for the new tokens, and turn OpenIddict's "this
// refresh token was already redeemed" signal into FAMILY revocation (ADR-0007 / T4).
[ApiController]
public sealed class TokenController : Controller
{
    private readonly IOpenIddictTokenManagerFacade _family;
    public TokenController(IOpenIddictTokenManagerFacade family) => _family = family;

    [HttpPost("/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Not an OpenID Connect request.");

        if (request.IsClientCredentialsGrantType())
        {
            var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            id.SetClaim(Claims.Subject, request.ClientId);
            id.SetScopes(request.GetScopes());
            id.SetDestinations(_ => new[] { Destinations.AccessToken });
            return SignIn(new ClaimsPrincipal(id), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // The principal stored with the code/refresh token; OpenIddict has already
            // validated it. For refresh, OpenIddict rejects a REUSED (redeemed) token
            // with invalid_grant before reaching here — that rejection is wired to
            // RevokeFamilyAsync via the OpenIddict event handler (see OnReuse below).
            var result = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = result.Principal!;

            // Re-assert destinations for the freshly minted tokens.
            foreach (var claim in principal.Claims)
                claim.SetDestinations(claim.Type switch
                {
                    Claims.Name or Claims.Email or Claims.EmailVerified
                        => new[] { Destinations.IdentityToken },
                    "acr" or "amr"
                        => new[] { Destinations.IdentityToken, Destinations.AccessToken },
                    _ => new[] { Destinations.AccessToken },
                });

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType,
            }));
    }
}
