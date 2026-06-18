using System.Collections.Immutable;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest extension
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OidcProvider.Api.Models;
using OidcProvider.Core.Data;
using OidcProvider.Core.Entities;
using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Controllers;

// Realizes docs/oidc-provider/authorize-controller.md on OpenIddict passthrough.
// OpenIddict has already validated PKCE presence, response_type and the EXACT
// redirect_uri match before handing control here (threats T2/T11/T12).
public sealed class AuthorizeController : Controller
{
    private readonly IUserSession _sessions;
    private readonly IUserService _users;
    private readonly IConsentStore _consents;
    private readonly IPairwiseSubjects _ppid;
    private readonly AuthDbContext _db;
    private readonly IAntiforgery _antiforgery;
    private readonly IAuditLog _audit;
    private readonly IOpenIddictApplicationManager _apps;
    private readonly IConfiguration _cfg;

    public AuthorizeController(IUserSession sessions, IUserService users,
        IConsentStore consents, IPairwiseSubjects ppid, AuthDbContext db, IAntiforgery antiforgery,
        IAuditLog audit, IOpenIddictApplicationManager apps, IConfiguration cfg)
        => (_sessions, _users, _consents, _ppid, _db, _antiforgery, _audit, _apps, _cfg)
           = (sessions, users, consents, ppid, db, antiforgery, audit, apps, cfg);

    [HttpGet("/authorize"), HttpPost("/authorize")]
    [IgnoreAntiforgeryToken] // CSRF defense here is the mandatory `state` param (T5)
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Not an OpenID Connect request.");

        // ADR-0011: PKCE mandatory by default (OAuth 2.1). `Oidc:Pkce:Required=false` relaxes it to
        // recommended (still S256-only when present) — e.g. to serve the legacy OIDC Basic profile,
        // which predates mandatory PKCE. Production keeps the default (required). [T11]
        if (request.CodeChallenge is null)
        {
            if (_cfg.GetValue("Oidc:Pkce:Required", true))
                return Reject(Errors.InvalidRequest, "PKCE with S256 is required.");
        }
        else if (request.CodeChallengeMethod != CodeChallengeMethods.Sha256)
            return Reject(Errors.InvalidRequest, "Only S256 PKCE is allowed (plain is rejected).");

        var promptNone = request.HasPromptValue("none"); // OIDC prompt=none

        // --- ResolveSession ---
        var sid = User.FindFirst("sid")?.Value;
        var session = sid is null ? null : await _sessions.GetAsync(sid);
        var maxAgeExceeded = session is not null && request.MaxAge is long age &&
            session.AuthTime < DateTimeOffset.UtcNow.AddSeconds(-age);

        if (session is null || maxAgeExceeded || request.HasPromptValue("login"))
        {
            if (promptNone) return Reject(Errors.LoginRequired, "Interactive login required.");
            // prompt=login forces re-auth ONCE — this Challenge IS that forced login, so strip
            // `login` from the return URL's prompt; otherwise the post-login /authorize re-prompts
            // in a loop. [OIDC: prompt=login is satisfied once the user (re-)authenticates]
            var returnQuery = request.HasPromptValue("login")
                ? QueryWithoutPromptLogin(Request.Query)
                : Request.QueryString.ToString();
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties { RedirectUri = Request.Path + returnQuery });
        }

        var user = await _users.GetAsync(session.UserId);
        if (user is null)
        {
            // Stale session: the user no longer exists (e.g. after a data reset). Clear it
            // and re-authenticate rather than dead-ending with an error.
            if (sid is not null) await _sessions.RevokeAsync(sid);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (promptNone) return Reject(Errors.LoginRequired, "Re-authentication required.");
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString });
        }

        // --- StepUp (acr / MFA) ---
        var requiredAcr = AcrPolicy.Resolve(request.GetAcrValues(), user.MfaMethods.Count > 0);
        if (!session.SatisfiesAcr(requiredAcr))
        {
            // If MFA is required but the user has no enrolled factor, fail clearly instead of
            // redirecting into an unsatisfiable /account/mfa loop. [code review #5]
            if (requiredAcr == AcrPolicy.Mfa && user.MfaMethods.Count == 0)
                return Reject("unmet_authentication_requirements", // OIDC / RFC 9470
                    "Requested acr requires a second factor, but the user has none enrolled.");
            if (promptNone) return Reject(Errors.LoginRequired, "Step-up authentication required.");
            var kind = user.MfaMethods[0].Kind == MfaKind.WebAuthn ? "webauthn-page" : "mfa";
            return Redirect($"/account/{kind}?returnUrl={Uri.EscapeDataString(Request.Path + Request.QueryString)}");
        }

        // --- Consent (T8) ---
        var requested = request.GetScopes();
        var consent = await _consents.GetActiveAsync(user.Id, request.ClientId!);
        // First-party/trusted clients (ConsentType=Implicit) skip the prompt; others need a
        // recorded grant covering the requested scopes.
        var app = await _apps.FindByClientIdAsync(request.ClientId!);
        var implicitConsent = app is not null &&
            await _apps.GetConsentTypeAsync(app) == ConsentTypes.Implicit;
        var covered = implicitConsent ||
            (consent is not null && requested.All(s => consent.ScopesGranted.Contains(s)));
        if (!covered)
        {
            if (promptNone) return Reject(Errors.ConsentRequired, "User consent required.");
            if (HttpContext.Request.Method == "GET")
            {
                // GET renders the consent form; the request params come from the query.
                var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
                var vm = new ConsentViewModel
                {
                    ClientId = request.ClientId!,
                    Scopes = requested.ToList(),
                    Parameters = HttpContext.Request.Query
                        .Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value.ToString()))
                        .ToList(),
                };
                return View("Consent", vm);
            }
            // POST = the consent form submission → validate the antiforgery token (first-party
            // CSRF defense for the consent UI; the OAuth `state` defends the redirect leg, T5).
            try { await _antiforgery.ValidateRequestAsync(HttpContext); }
            catch (AntiforgeryValidationException)
            { return BadRequest("Invalid or missing antiforgery token."); }
            if (Request.Form["submit"] != "accept")
                return Reject(Errors.AccessDenied, "User denied consent.");
            await _consents.RecordAsync(user.Id, request.ClientId!, requested);
            await _audit.WriteAsync("consent.granted", user.Id, request.ClientId,
                new { scopes = requested.ToArray() });
        }

        // --- IssueCode: build the principal OpenIddict mints the code from ---
        var policy = await _db.ClientPolicies.FindAsync(request.ClientId);
        var sector = policy?.SectorIdentifier ?? request.ClientId!;

        var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, await _ppid.ForAsync(user.Id, sector)); // ADR-0010
        identity.SetClaim(Claims.Email, user.Email);
        identity.SetClaim(Claims.EmailVerified, user.EmailVerified); // JSON boolean, not "True" [code review #1]
        identity.SetClaim("acr", session.Acr);
        identity.SetClaim("sid", sid); // session id → id_token; enables back-channel logout matching
        // auth_time (seconds) — REQUIRED by OIDC when max_age is used and for prompt=login
        // verification; emitted as a JSON number via the Integer64 value type.
        identity.AddClaim(new Claim("auth_time", session.AuthTime.ToUnixTimeSeconds().ToString(),
            ClaimValueTypes.Integer64));
        identity.SetClaims("amr", session.Amr.ToImmutableArray());

        // Remember this RP under the session so back-channel logout can notify it later (OIDC BCL).
        await _sessions.AddClientAsync(sid!, request.ClientId!);

        // `profile` scope → emit the profile claims (name, ...) the user actually has.
        // Previously ProfileClaimsJson was stored but never read, so profile was a no-op. [code review #2]
        if (requested.Contains(Scopes.Profile) && !string.IsNullOrWhiteSpace(user.ProfileClaimsJson))
        {
            using var profile = System.Text.Json.JsonDocument.Parse(user.ProfileClaimsJson);
            if (profile.RootElement.TryGetProperty("name", out var name) && name.GetString() is { } n)
                identity.SetClaim(Claims.Name, n);
        }

        identity.SetScopes(requested);
        identity.SetResources((request.Resources ?? Array.Empty<string?>())
            .Where(r => !string.IsNullOrEmpty(r)).Select(r => r!).ToArray()); // RFC 8707 audience restriction

        // RFC 9396 Rich Authorization Requests: carry the structured `authorization_details` grant
        // into the access token (present in the query on GET, reposted in the consent form on POST).
        var authDetails = Request.Query["authorization_details"].FirstOrDefault()
            ?? (Request.HasFormContentType ? Request.Form["authorization_details"].FirstOrDefault() : null);
        if (!string.IsNullOrEmpty(authDetails))
        {
            try
            {
                using var d = System.Text.Json.JsonDocument.Parse(authDetails);
                if (d.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array)
                    return Reject(Errors.InvalidRequest, "authorization_details must be a JSON array.");
            }
            catch { return Reject(Errors.InvalidRequest, "authorization_details must be valid JSON."); }
            // JSON_ARRAY value type → always serialized as a JSON array (a single JSON claim would
            // otherwise be collapsed to a scalar object; RFC 9396 requires an array).
            identity.AddClaim(new Claim("authorization_details", authDetails, "JSON_ARRAY"));
        }

        identity.SetDestinations(OidcDestinations.For);

        // OpenIddict now binds nonce, computes at_hash, mints the single-use ≤60s code
        // (bound to client/redirect_uri/code_challenge/sub/scope), and 302s with code+state+iss.
        return SignIn(new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // Rebuild the query string with "login" removed from the prompt parameter (drop prompt if empty).
    private static string QueryWithoutPromptLogin(IQueryCollection query)
    {
        var d = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var kv in query)
        {
            if (kv.Key == "prompt")
            {
                var rest = string.Join(' ', kv.Value.ToString()
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(p => p != "login"));
                if (!string.IsNullOrEmpty(rest)) d["prompt"] = rest;
            }
            else d[kv.Key] = kv.Value.ToString();
        }
        return QueryString.Create(d).ToString();
    }

    private IActionResult Reject(string error, string description) => Forbid(
        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        properties: new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }));

}
