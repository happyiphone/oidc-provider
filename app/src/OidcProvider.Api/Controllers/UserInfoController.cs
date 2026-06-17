using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Controllers;

// OIDC Core §5.3. The access token is validated by OpenIddict before this runs (expired/
// invalid → 401). `sub` MUST equal the id_token's pairwise sub (ADR-0010).
// DPoP (RFC 9449): if the token is sender-constrained (carries cnf.jkt), it MUST be
// presented as `Authorization: DPoP <token>` with a valid proof whose key thumbprint
// matches cnf.jkt and whose `ath` hashes this token — otherwise it's a stolen bearer.
[ApiController]
public sealed class UserInfoController : Controller
{
    private readonly IDpopValidator _dpop;
    public UserInfoController(IDpopValidator dpop) => _dpop = dpop;

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("/userinfo"), HttpPost("/userinfo"), Produces("application/json")]
    public async Task<IActionResult> UserInfo()
    {
        // Sender-constraining check: a cnf-bound token may only be used with DPoP.
        if (User.GetClaim("cnf") is { } cnfJson)
        {
            var boundJkt = JsonDocument.Parse(cnfJson).RootElement.GetProperty("jkt").GetString();
            var token = HttpContext.Items["dpop_access_token"] as string;   // set by the normalizer
            var proof = Request.Headers["DPoP"].FirstOrDefault();
            if (token is null || string.IsNullOrEmpty(proof))
                return Unauthorized();   // cnf-bound token presented without DPoP

            var htu = $"{Request.Scheme}://{Request.Host}{Request.Path}";
            var jkt = await _dpop.ValidateAsync(proof, Request.Method, htu, token);
            if (jkt is null || jkt != boundJkt)
                return Unauthorized();   // bad proof, ath mismatch, replay, or wrong key
        }

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
