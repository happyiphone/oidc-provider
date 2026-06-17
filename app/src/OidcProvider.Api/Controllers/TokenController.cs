using System.Security.Claims;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest extension
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OidcProvider.Core.Services;
using OidcProvider.Core.Signing;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Controllers;

// Token endpoint passthrough. OpenIddict performs client auth, code single-use +
// redirect_uri + PKCE checks, and refresh-token validation/rolling BEFORE this runs.
// Our job: bind DPoP (RFC 9449) when proof is present, rebuild the principal, and let the
// refresh-reuse handler turn a redeemed-token replay into FAMILY revocation (ADR-0007/T4).
[ApiController]
public sealed class TokenController : Controller
{
    private readonly IOpenIddictTokenManagerFacade _family;
    private readonly IDpopValidator _dpop;
    public TokenController(IOpenIddictTokenManagerFacade family, IDpopValidator dpop)
        => (_family, _dpop) = (family, dpop);

    [HttpPost("/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Not an OpenID Connect request.");

        // DPoP: if the client presents a proof, validate it (htm=POST, htu=this endpoint)
        // and bind the key thumbprint into the access token as cnf.jkt (sender-constraining).
        string? jkt = null;
        if (Request.Headers["DPoP"].FirstOrDefault() is { Length: > 0 } proof)
        {
            var htu = $"{Request.Scheme}://{Request.Host}{Request.Path}";
            jkt = await _dpop.ValidateAsync(proof, "POST", htu);
            if (jkt is null)
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: Error("invalid_dpop_proof", "The DPoP proof is invalid, stale, or replayed."));
        }

        if (request.IsClientCredentialsGrantType())
        {
            var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            id.SetClaim(Claims.Subject, request.ClientId);
            id.SetScopes(request.GetScopes());
            BindCnf(id, jkt);
            id.SetDestinations(OidcDestinations.For);
            return SignIn(new ClaimsPrincipal(id), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            var result = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = result.Principal!;
            BindCnf((ClaimsIdentity)principal.Identity!, jkt);
            principal.SetDestinations(OidcDestinations.For);  // shared id/access-token policy
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: Error(Errors.UnsupportedGrantType, "Unsupported grant type."));
    }

    // cnf = { "jkt": "<thumbprint>" } — emitted as a nested JSON object in the access token
    // (ValueType "JSON" tells the JWT handler not to stringify it). RFC 9449 §6.
    private static void BindCnf(ClaimsIdentity identity, string? jkt)
    {
        if (jkt is null) return;
        identity.AddClaim(new Claim("cnf", $"{{\"jkt\":\"{jkt}\"}}", "JSON")); // RFC 7800 confirmation
    }

    private static AuthenticationProperties Error(string error, string description) => new(
        new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        });
}
