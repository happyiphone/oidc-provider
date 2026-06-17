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

    public AuthorizeController(IUserSession sessions, IUserService users,
        IConsentStore consents, IPairwiseSubjects ppid, AuthDbContext db, IAntiforgery antiforgery)
        => (_sessions, _users, _consents, _ppid, _db, _antiforgery)
           = (sessions, users, consents, ppid, db, antiforgery);

    [HttpGet("/authorize"), HttpPost("/authorize")]
    [IgnoreAntiforgeryToken] // CSRF defense here is the mandatory `state` param (T5)
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Not an OpenID Connect request.");

        // ADR-0011 belt-and-braces: require S256 explicitly (T11).
        if (request.CodeChallenge is null ||
            request.CodeChallengeMethod != CodeChallengeMethods.Sha256)
            return Reject(Errors.InvalidRequest, "PKCE with S256 is required.");

        var promptNone = request.HasPromptValue("none"); // OIDC prompt=none

        // --- ResolveSession ---
        var sid = User.FindFirst("sid")?.Value;
        var session = sid is null ? null : await _sessions.GetAsync(sid);
        var maxAgeExceeded = session is not null && request.MaxAge is long age &&
            session.AuthTime < DateTimeOffset.UtcNow.AddSeconds(-age);

        if (session is null || maxAgeExceeded || request.HasPromptValue("login"))
        {
            if (promptNone) return Reject(Errors.LoginRequired, "Interactive login required.");
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                { RedirectUri = Request.Path + Request.QueryString });
        }

        var user = await _users.GetAsync(session.UserId);
        if (user is null) return Reject(Errors.AccessDenied, "Unknown user.");

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
        var covered = consent is not null && requested.All(s => consent.ScopesGranted.Contains(s));
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
        identity.SetClaims("amr", session.Amr.ToImmutableArray());

        // `profile` scope → emit the profile claims (name, ...) the user actually has.
        // Previously ProfileClaimsJson was stored but never read, so profile was a no-op. [code review #2]
        if (requested.Contains(Scopes.Profile) && !string.IsNullOrWhiteSpace(user.ProfileClaimsJson))
        {
            using var profile = System.Text.Json.JsonDocument.Parse(user.ProfileClaimsJson);
            if (profile.RootElement.TryGetProperty("name", out var name) && name.GetString() is { } n)
                identity.SetClaim(Claims.Name, n);
        }

        identity.SetScopes(requested);
        identity.SetDestinations(GetDestinations);

        // OpenIddict now binds nonce, computes at_hash, mints the single-use ≤60s code
        // (bound to client/redirect_uri/code_challenge/sub/scope), and 302s with code+state+iss.
        return SignIn(new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IEnumerable<string> GetDestinations(Claim claim) => claim.Type switch
    {
        Claims.Name or Claims.Email or Claims.EmailVerified
            => new[] { Destinations.IdentityToken },
        "acr" or "amr"
            => new[] { Destinations.IdentityToken, Destinations.AccessToken },
        _ => new[] { Destinations.AccessToken },
    };

    private IActionResult Reject(string error, string description) => Forbid(
        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        properties: new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        }));

}
