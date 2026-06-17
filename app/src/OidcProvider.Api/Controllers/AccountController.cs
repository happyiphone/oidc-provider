using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OidcProvider.Api.Models;
using OidcProvider.Core.Entities;
using OidcProvider.Core.Services;

namespace OidcProvider.Api.Controllers;

// Login + MFA (TOTP and WebAuthn) live OUTSIDE the protocol controllers so credential
// handling never mixes with token issuance. On success we create a Redis-backed session
// (ADR-0006) with a FRESH id (anti-fixation, threat T13) and drop a cookie carrying only
// the session id. HTML forms use antiforgery tokens; the WebAuthn JSON endpoints are
// defended by the server-issued, session-bound challenge.
public sealed class AccountController : Controller
{
    private readonly IUserService _users;
    private readonly IUserSession _sessions;
    private readonly ITotpService _totp;
    private readonly IWebAuthnService _webauthn;
    private readonly ILoginThrottle _throttle;
    private readonly IConsentStore _consents;
    private readonly IAuditLog _audit;
    public AccountController(IUserService users, IUserSession sessions, ITotpService totp,
        IWebAuthnService webauthn, ILoginThrottle throttle, IConsentStore consents, IAuditLog audit)
        => (_users, _sessions, _totp, _webauthn, _throttle, _consents, _audit)
           = (users, sessions, totp, webauthn, throttle, consents, audit);

    [HttpGet("/account/login")]
    public IActionResult LoginPage([FromQuery] string? returnUrl)
        => View("Login", new LoginViewModel { ReturnUrl = returnUrl });

    [HttpPost("/account/login"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(
        [FromForm] string? username, [FromForm] string? password, [FromForm] string? returnUrl)
    {
        var throttleKey = username ?? "";
        // Brute-force lockout: refuse once too many recent failures, even with the right password.
        if (await _throttle.IsLockedAsync(throttleKey))
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl, Error = "Too many attempts. Try again later." });

        var user = await _users.ValidatePasswordAsync(username ?? "", password ?? "");
        if (user is null)
        {
            await _throttle.RecordFailureAsync(throttleKey);
            return View("Login", new LoginViewModel { ReturnUrl = returnUrl, Error = "Invalid credentials." });
        }
        await _throttle.ResetAsync(throttleKey);   // clear the counter on success

        if (user.MfaMethods.Count > 0)
        {
            // Establish a PARTIAL (acr=pwd) session, then route to the right second factor.
            await EstablishSessionAsync(user.Id, AcrPolicy.Pwd, new[] { "pwd" });
            var ret = Uri.EscapeDataString(returnUrl ?? "/");
            return Redirect(user.MfaMethods[0].Kind == MfaKind.WebAuthn
                ? $"/account/webauthn-page?returnUrl={ret}"
                : $"/account/mfa?returnUrl={ret}");
        }

        await EstablishSessionAsync(user.Id, AcrPolicy.Pwd, new[] { "pwd" });
        return Redirect(returnUrl ?? "/");
    }

    // ---- TOTP (RFC 6238) ----
    [HttpGet("/account/mfa")]
    public IActionResult MfaPage([FromQuery] string? returnUrl)
        => View("Mfa", new MfaViewModel { ReturnUrl = returnUrl });

    [HttpPost("/account/mfa"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Mfa([FromForm] string? code, [FromForm] string? returnUrl)
    {
        var (sid, session) = await CurrentSessionAsync();
        if (session is null) return Redirect("/account/login");
        var user = await _users.GetAsync(session.UserId);
        var totp = user?.MfaMethods.FirstOrDefault(m => m.Kind == MfaKind.Totp);
        if (totp is null || !_totp.Verify(totp.SecretRef, code ?? ""))
            return View("Mfa", new MfaViewModel { ReturnUrl = returnUrl, Error = "Invalid code." });

        await _sessions.RevokeAsync(sid!);
        await EstablishSessionAsync(session.UserId, AcrPolicy.Mfa, new[] { "pwd", "otp" });
        return Redirect(returnUrl ?? "/");
    }

    // ---- WebAuthn / FIDO2 assertion (second factor) ----
    [HttpGet("/account/webauthn-page")]
    public IActionResult WebAuthnPage([FromQuery] string? returnUrl)
        => Content(
            "<!doctype html><meta charset=utf-8><title>Security key</title>" +
            "<p>Use your security key / passkey. (A real UI calls <code>navigator.credentials.get()</code> " +
            "against <code>/account/webauthn/options</code> then posts the assertion to " +
            "<code>/account/webauthn</code>.)</p>", "text/html");

    [HttpPost("/account/webauthn/register/options")]
    public async Task<IActionResult> WebAuthnRegisterOptions()
    {
        var (_, session) = await CurrentSessionAsync();
        if (session is null) return Unauthorized();
        var user = await _users.GetAsync(session.UserId);
        if (user is null) return Unauthorized();
        var sid = User.FindFirst("sid")!.Value;
        return Ok(await _webauthn.NewRegistrationOptionsAsync(sid, user.Id, user.Username ?? user.Id.ToString()));
    }

    [HttpPost("/account/webauthn/register")]
    public async Task<IActionResult> WebAuthnRegister([FromBody] WebAuthnAttestation attestation)
    {
        var (_, session) = await CurrentSessionAsync();
        if (session is null) return Unauthorized();
        var user = await _users.GetAsync(session.UserId);
        if (user is null) return Unauthorized();
        var sid = User.FindFirst("sid")!.Value;

        var cred = await _webauthn.VerifyRegistrationAsync(sid, attestation);
        if (cred is null) return BadRequest(new { error = "attestation_failed" });

        await _users.AddMfaMethodAsync(new UserMfaMethod
        {
            UserId = user.Id,
            Kind = MfaKind.WebAuthn,
            SecretRef = cred.CredentialId,
            PublicKey = cred.PublicKey,
            SignCount = cred.SignCount,
            Label = "Security key",
        });
        return Ok(new { ok = true, credentialId = cred.CredentialId });
    }

    [HttpPost("/account/webauthn/options")]
    public async Task<IActionResult> WebAuthnOptions()
    {
        var (_, session) = await CurrentSessionAsync();
        if (session is null) return Unauthorized();
        var user = await _users.GetAsync(session.UserId);
        var cred = user?.MfaMethods.FirstOrDefault(m => m.Kind == MfaKind.WebAuthn);
        if (cred is null) return BadRequest("No WebAuthn credential enrolled.");
        var sid = User.FindFirst("sid")!.Value;
        var opts = await _webauthn.NewAssertionOptionsAsync(sid, cred);
        return Ok(opts);
    }

    [HttpPost("/account/webauthn")]
    public async Task<IActionResult> WebAuthn([FromBody] WebAuthnAssertion assertion,
        [FromQuery] string? returnUrl)
    {
        var (sid, session) = await CurrentSessionAsync();
        if (session is null) return Unauthorized();
        var user = await _users.GetAsync(session.UserId);
        var cred = user?.MfaMethods.FirstOrDefault(m => m.Kind == MfaKind.WebAuthn);
        if (cred is null) return BadRequest("No WebAuthn credential enrolled.");

        if (!await _webauthn.VerifyAssertionAsync(sid!, cred, assertion))
            return BadRequest(new { error = "assertion_failed" });

        await _users.SaveAsync();                 // persist updated signCount (clone detection)
        await _sessions.RevokeAsync(sid!);
        await EstablishSessionAsync(session.UserId, AcrPolicy.Mfa, new[] { "pwd", "webauthn" });
        return Ok(new { ok = true, returnUrl = returnUrl ?? "/" });
    }

    [HttpPost("/account/logout"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        if (User.FindFirst("sid")?.Value is { } sid) await _sessions.RevokeAsync(sid);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok();
    }

    // ---- Consent management (view + revoke the apps you've authorized) ----
    [HttpGet("/account/consents")]
    public async Task<IActionResult> Consents()
    {
        var (_, session) = await CurrentSessionAsync();
        if (session is null) return Redirect("/account/login?returnUrl=/account/consents");
        var rows = (await _consents.ListActiveAsync(session.UserId))
            .Select(c => new ConsentRow { ClientId = c.ClientId, Scopes = c.ScopesGranted }).ToList();
        return View("Consents", new ConsentsListViewModel { Consents = rows });
    }

    [HttpPost("/account/consents/revoke"), ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeConsent([FromForm] string clientId)
    {
        var (_, session) = await CurrentSessionAsync();
        if (session is null) return Redirect("/account/login");
        await _consents.RevokeAsync(session.UserId, clientId);
        await _audit.WriteAsync("consent.revoked", session.UserId, clientId);
        return Redirect("/account/consents");
    }

    private async Task<(string? sid, UserSessionData? session)> CurrentSessionAsync()
    {
        var sid = User.FindFirst("sid")?.Value;
        var session = sid is null ? null : await _sessions.GetAsync(sid);
        return (sid, session);
    }

    private async Task EstablishSessionAsync(Guid userId, string acr, string[] amr)
    {
        var sid = await _sessions.CreateAsync(
            new UserSessionData(userId, DateTimeOffset.UtcNow, acr, amr), TimeSpan.FromHours(8));
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
        identity.AddClaim(new Claim("sid", sid));
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId.ToString()));
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = false });
    }
}
