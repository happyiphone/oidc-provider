using System.Security.Claims;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest extension
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OidcProvider.Core.Data;
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
    public const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    private readonly IOpenIddictTokenManagerFacade _family;
    private readonly IDpopValidator _dpop;
    private readonly AuthDbContext _db;
    private readonly StackExchange.Redis.IConnectionMultiplexer _mux;
    private readonly IPairwiseSubjects _ppid;
    private readonly Microsoft.Extensions.Options.IOptionsMonitor<OpenIddict.Server.OpenIddictServerOptions> _server;
    private readonly IConfiguration _cfg;
    public TokenController(IOpenIddictTokenManagerFacade family, IDpopValidator dpop, AuthDbContext db,
        StackExchange.Redis.IConnectionMultiplexer mux, IPairwiseSubjects ppid,
        Microsoft.Extensions.Options.IOptionsMonitor<OpenIddict.Server.OpenIddictServerOptions> server,
        IConfiguration cfg)
        => (_family, _dpop, _db, _mux, _ppid, _server, _cfg) = (family, dpop, db, mux, ppid, server, cfg);

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

        // Per-client policy (ADR-0009): a DPoP-bound client must present a proof.
        if (request.ClientId is { } clientId && jkt is null &&
            await _db.ClientPolicies.FirstOrDefaultAsync(p => p.ClientId == clientId) is { DpopBound: true })
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: Error("invalid_dpop_proof", "This client requires a DPoP proof."));

        // mTLS (RFC 8705 §3): a TLS-terminating proxy forwards the validated client cert; bind its
        // SHA-256 thumbprint as cnf.x5t#S256 (certificate-bound access token), like DPoP's jkt.
        if (Request.Headers["X-Client-Cert"].FirstOrDefault() is { Length: > 0 } certPem)
        {
            try
            {
                using var cert = System.Security.Cryptography.X509Certificates.X509Certificate2
                    .CreateFromPem(Uri.UnescapeDataString(certPem));
                _x5t = OidcProvider.Core.Base64UrlText.Encode(
                    System.Security.Cryptography.SHA256.HashData(cert.RawData));
            }
            catch { /* malformed cert header → simply no binding */ }
        }

        // CIBA poll (custom flow): redeem the approved backchannel request, then mint via OpenIddict.
        if (request.GrantType == Ciba.GrantType)
            return await ExchangeCibaAsync(request, jkt);

        // Token Exchange (RFC 8693): swap a token we issued for a downscoped/delegated one.
        if (request.GrantType == TokenExchangeGrant)
            return ExchangeTokenExchange(request, jkt);

        if (request.IsClientCredentialsGrantType())
        {
            var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            id.SetClaim(Claims.Subject, request.ClientId);
            id.SetScopes(request.GetScopes());
            id.SetResources((request.Resources ?? Array.Empty<string?>())
                .Where(r => !string.IsNullOrEmpty(r)).Select(r => r!).ToArray()); // RFC 8707
            BindCnf(id, jkt);
            id.SetDestinations(OidcDestinations.For);
            return SignIn(new ClaimsPrincipal(id), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // auth code / refresh / device_code all redeem a server-stored grant: OpenIddict
        // authenticates the code and hands back the principal it was issued with.
        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType() ||
            request.IsDeviceCodeGrantType())
        {
            var result = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = result.Principal!;
            var pid = (ClaimsIdentity)principal.Identity!;
            BindCnf(pid, jkt);
            // RFC 9396: re-stamp authorization_details as JSON_ARRAY here (the access token is minted
            // at this endpoint, and the value type doesn't survive the code round-trip — a single
            // element would otherwise serialize as a scalar object).
            if (pid.FindFirst("authorization_details") is { } ad)
            {
                var val = ad.Value.TrimStart();
                if (!val.StartsWith("[")) val = "[" + ad.Value + "]";
                pid.RemoveClaim(ad);
                pid.AddClaim(new Claim("authorization_details", val, "JSON_ARRAY"));
            }
            principal.SetDestinations(OidcDestinations.For);  // shared id/access-token policy
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: Error(Errors.UnsupportedGrantType, "Unsupported grant type."));
    }

    // CIBA token poll: look up the auth_req_id, return the RFC 8628-style poll error while pending,
    // or (once the user approved on their device) build the principal and let OpenIddict mint tokens.
    private async Task<IActionResult> ExchangeCibaAsync(OpenIddictRequest request, string? jkt)
    {
        var authReqId = request.GetParameter("auth_req_id")?.Value?.ToString();
        if (string.IsNullOrEmpty(authReqId))
            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: Error(Errors.InvalidRequest, "Missing auth_req_id."));

        var redis = _mux.GetDatabase();
        var raw = await redis.StringGetAsync(Ciba.Key(authReqId));
        if (raw.IsNullOrEmpty)
            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties: Error("expired_token", "Unknown or expired auth_req_id."));
        var rec = System.Text.Json.JsonSerializer.Deserialize<CibaRequest>(raw!)!;
        if (rec.ClientId != request.ClientId)
            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties: Error(Errors.InvalidGrant, "auth_req_id belongs to another client."));
        if (rec.Status == "pending")
            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties: Error("authorization_pending", "The user has not yet approved."));
        if (rec.Status == "denied")
            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties: Error(Errors.AccessDenied, "The user denied the request."));

        await redis.KeyDeleteAsync(Ciba.Key(authReqId)); // single use

        var sector = request.ClientId!;
        var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        id.SetClaim(Claims.Subject, await _ppid.ForAsync(rec.UserId, sector));
        id.SetScopes(rec.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        BindCnf(id, jkt);
        id.SetDestinations(OidcDestinations.For);
        return SignIn(new ClaimsPrincipal(id), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // RFC 8693 token exchange. The subject_token must be an access token WE issued; we validate it
    // against our own signing keys, then mint a new token for the (optionally) requested
    // audience/scope. An actor_token adds an `act` delegation claim (RFC 8693 §4.1).
    private IActionResult ExchangeTokenExchange(OpenIddictRequest request, string? jkt)
    {
        var subjectToken = request.GetParameter("subject_token")?.Value?.ToString();
        if (string.IsNullOrEmpty(subjectToken))
            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: Error(Errors.InvalidRequest, "Missing subject_token."));

        var keys = _server.CurrentValue.SigningCredentials.Select(c => c.Key).ToList();
        var tvp = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidIssuer = _cfg["Oidc:Issuer"],
            IssuerSigningKeys = keys,
            ValidateAudience = false, // subject token's aud is some resource server
            ValidateLifetime = true,
        };
        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        var result = handler.ValidateTokenAsync(subjectToken, tvp).GetAwaiter().GetResult();
        if (!result.IsValid)
            return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: Error(Errors.InvalidGrant, "subject_token is invalid or expired."));

        var subjectJwt = (Microsoft.IdentityModel.JsonWebTokens.JsonWebToken)result.SecurityToken;
        var subject = subjectJwt.Subject;
        var subjectScopes = subjectJwt.TryGetPayloadValue<string>("scope", out var sc)
            ? sc.Split(' ', StringSplitOptions.RemoveEmptyEntries) : Array.Empty<string>();
        var requested = request.GetScopes();
        var effective = requested.Length > 0 ? requested.Intersect(subjectScopes).ToArray() : subjectScopes;

        var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        id.SetClaim(Claims.Subject, subject);
        id.SetScopes(effective);
        id.SetResources((request.Resources ?? Array.Empty<string?>())
            .Where(r => !string.IsNullOrEmpty(r)).Select(r => r!).ToArray());

        // Delegation: an actor_token (also one of ours) becomes the `act` claim.
        var actorToken = request.GetParameter("actor_token")?.Value?.ToString();
        if (!string.IsNullOrEmpty(actorToken))
        {
            var actor = handler.ValidateTokenAsync(actorToken, tvp).GetAwaiter().GetResult();
            if (actor.IsValid)
                id.AddClaim(new Claim("act",
                    $"{{\"sub\":\"{((Microsoft.IdentityModel.JsonWebTokens.JsonWebToken)actor.SecurityToken).Subject}\"}}", "JSON"));
        }

        BindCnf(id, jkt);
        id.SetDestinations(OidcDestinations.For);
        return SignIn(new ClaimsPrincipal(id), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private string? _x5t; // mTLS cert thumbprint for the current request (RFC 8705)

    // cnf = { "jkt": …, "x5t#S256": … } — sender-constraining confirmation (RFC 7800): DPoP key
    // thumbprint (RFC 9449) and/or mTLS certificate thumbprint (RFC 8705). Emitted as nested JSON.
    private void BindCnf(ClaimsIdentity identity, string? jkt)
    {
        var parts = new List<string>();
        if (jkt is not null) parts.Add($"\"jkt\":\"{jkt}\"");
        if (_x5t is not null) parts.Add($"\"x5t#S256\":\"{_x5t}\"");
        if (parts.Count == 0) return;
        identity.AddClaim(new Claim("cnf", "{" + string.Join(",", parts) + "}", "JSON"));
    }

    private static AuthenticationProperties Error(string error, string description) => new(
        new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        });
}
