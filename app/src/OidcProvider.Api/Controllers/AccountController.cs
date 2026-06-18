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
    private readonly IBackChannelLogoutNotifier _bcl;
    private readonly IConfiguration _cfg;
    public AccountController(IUserService users, IUserSession sessions, ITotpService totp,
        IWebAuthnService webauthn, ILoginThrottle throttle, IConsentStore consents, IAuditLog audit,
        IBackChannelLogoutNotifier bcl, IConfiguration cfg)
        => (_users, _sessions, _totp, _webauthn, _throttle, _consents, _audit, _bcl, _cfg)
           = (users, sessions, totp, webauthn, throttle, consents, audit, bcl, cfg);

    [HttpGet("/account/login")]
    public IActionResult LoginPage([FromQuery] string? returnUrl)
        => View("Login", new LoginViewModel
        {
            ReturnUrl = returnUrl,
            FederationName = _cfg["Oidc:Federation:DisplayName"],   // null/empty → no external button
        });

    // ---- Federation: log in via an external OIDC IdP ----
    [HttpGet("/account/external-login")]
    public IActionResult ExternalLogin([FromQuery] string? returnUrl)
    {
        if (string.IsNullOrEmpty(_cfg["Oidc:Federation:Authority"])) return NotFound();
        var redirect = $"/account/external-callback?returnUrl={Uri.EscapeDataString(returnUrl ?? "/")}";
        return Challenge(new AuthenticationProperties { RedirectUri = redirect }, "oidc-external");
    }

    [HttpGet("/account/external-callback")]
    public async Task<IActionResult> ExternalCallback([FromQuery] string? returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync("External");
        if (!result.Succeeded) return Redirect("/account/login");
        var p = result.Principal!;
        var email = p.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value ?? p.FindFirst("email")?.Value;
        var sub = p.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? p.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(email)) return BadRequest("The external IdP did not return an email.");

        var user = await _users.FindOrCreateFederatedAsync(email, sub ?? email);  // link by email
        await HttpContext.SignOutAsync("External");
        await EstablishSessionAsync(user.Id, AcrPolicy.Pwd, new[] { "ext" });
        await _audit.WriteAsync("login.federated", user.Id);
        return Redirect(returnUrl ?? "/");
    }

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

    // ---- WebAuthn / FIDO2 ----
    // Shared JS: base64url <-> ArrayBuffer helpers used by both ceremonies.
    private const string WebAuthnJs = @"
const b2b=b=>{let s='';for(const x of new Uint8Array(b))s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');};
const u2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');s+='='.repeat((4-s.length%4)%4);const d=atob(s),a=new Uint8Array(d.length);for(let i=0;i<d.length;i++)a[i]=d.charCodeAt(i);return a.buffer;};
function msg(t){document.getElementById('msg').textContent=t;}";

    // Security page: enroll a passkey / security key from the browser (real
    // navigator.credentials.create → attestation → /account/webauthn/register).
    [HttpGet("/account/security")]
    public IActionResult Security()
        => Content(
            "<!doctype html><meta charset=utf-8><title>Security</title>" +
            "<h1>Security keys / passkeys</h1>" +
            "<p>Register a passkey or hardware security key as a second factor.</p>" +
            "<button id=reg>Register a passkey</button> <span id=msg></span>" +
            "<script>" + WebAuthnJs + @"
document.getElementById('reg').onclick=async()=>{
  try{
    msg('…');
    const o=await (await fetch('/account/webauthn/register/options',{method:'POST'})).json();
    const c=await navigator.credentials.create({publicKey:{
      challenge:u2b(o.challenge), rp:{id:o.rpId,name:o.rpName},
      user:{id:u2b(o.userId),name:o.userName,displayName:o.userName},
      pubKeyCredParams:[{type:'public-key',alg:-7}],
      // residentKey:required → a discoverable passkey, usable for usernameless/passwordless login.
      authenticatorSelection:{residentKey:'required',requireResidentKey:true,userVerification:'preferred'},
      attestation:'none', timeout:60000}});
    const r=await fetch('/account/webauthn/register',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({Id:c.id,AttestationObject:b2b(c.response.attestationObject),ClientDataJSON:b2b(c.response.clientDataJSON)})});
    msg(r.ok?'✅ Passkey registered':'❌ '+(await r.text()));
  }catch(e){msg('❌ '+e);}
};
</script>", "text/html");

    // MFA step-up page: prove possession of an enrolled passkey
    // (navigator.credentials.get → assertion → /account/webauthn).
    [HttpGet("/account/webauthn-page")]
    public IActionResult WebAuthnPage([FromQuery] string? returnUrl)
        => Content(
            "<!doctype html><meta charset=utf-8><title>Security key</title>" +
            "<h1>Second factor</h1><p>Use your passkey / security key.</p>" +
            "<button id=go>Use security key</button> <span id=msg></span>" +
            "<script>" + WebAuthnJs + @"
async function auth(){
  try{
    msg('…');
    const o=await (await fetch('/account/webauthn/options',{method:'POST'})).json();
    const a=await navigator.credentials.get({publicKey:{
      challenge:u2b(o.challenge), rpId:o.rpId,
      allowCredentials:[{type:'public-key',id:u2b(o.credentialId)}],
      userVerification:'discouraged', timeout:60000}});
    const ru=new URLSearchParams(location.search).get('returnUrl')||'/';
    const r=await fetch('/account/webauthn?returnUrl='+encodeURIComponent(ru),{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({Id:a.id,AuthenticatorData:b2b(a.response.authenticatorData),ClientDataJSON:b2b(a.response.clientDataJSON),Signature:b2b(a.response.signature)})});
    if(r.ok){const j=await r.json();location.href=j.returnUrl||'/';}else{msg('❌ '+(await r.text()));}
  }catch(e){msg('❌ '+e);}
}
document.getElementById('go').onclick=auth; auth();
</script>", "text/html");

    // ---- Passwordless / passkey-as-primary login (usernameless WebAuthn) ----
    [HttpPost("/account/webauthn/login/options")]
    public async Task<IActionResult> WebAuthnLoginOptions()
    {
        var key = OidcProvider.Core.Base64UrlText.Encode(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        Response.Cookies.Append("wa_login", key, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = Request.IsHttps,   // dev http: not secure; prod https: secure
            MaxAge = TimeSpan.FromMinutes(5),
        });
        return Ok(await _webauthn.NewLoginOptionsAsync(key));
    }

    [HttpPost("/account/webauthn/login")]
    public async Task<IActionResult> WebAuthnLogin([FromBody] WebAuthnAssertion assertion,
        [FromQuery] string? returnUrl)
    {
        var key = Request.Cookies["wa_login"];
        if (string.IsNullOrEmpty(key)) return BadRequest(new { error = "no_challenge" });
        var user = await _users.FindByWebAuthnCredentialAsync(assertion.Id);
        var cred = user?.MfaMethods.FirstOrDefault(m => m.Kind == MfaKind.WebAuthn && m.SecretRef == assertion.Id);
        if (user is null || cred is null) return BadRequest(new { error = "unknown_credential" });

        if (!await _webauthn.VerifyAssertionAsync(key, cred, assertion))
            return BadRequest(new { error = "assertion_failed" });

        await _users.SaveAsync();                       // persist signCount (clone detection)
        Response.Cookies.Delete("wa_login");
        // Passwordless passkey is phishing-resistant → treat as strong (MFA-level) auth.
        await EstablishSessionAsync(user.Id, AcrPolicy.Mfa, new[] { "webauthn" });
        await _audit.WriteAsync("login.passwordless", user.Id);
        return Ok(new { ok = true, returnUrl = returnUrl ?? "/" });
    }

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

    // Change password → revoke all tokens + sessions issued under the old credential, then
    // re-establish THIS device's session so the user stays logged in where they changed it.
    [HttpPost("/account/password"), ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(
        [FromForm] string? currentPassword, [FromForm] string? newPassword)
    {
        var (_, session) = await CurrentSessionAsync();
        if (session is null) return Unauthorized();
        // Snapshot every session's RPs BEFORE the change wipes them, so we can notify them after.
        var sessionClients = await _sessions.GetUserSessionClientsAsync(session.UserId);
        if (!await _users.ChangePasswordAsync(session.UserId, currentPassword ?? "", newPassword ?? ""))
            return BadRequest(new { error = "password_change_failed" });
        await _bcl.NotifyAllSessionsAsync(session.UserId, sessionClients); // BCL across all devices
        await _audit.WriteAsync("password.changed", session.UserId);
        await EstablishSessionAsync(session.UserId, session.Acr, session.Amr); // fresh session here
        return Ok();
    }

    // "Log out everywhere" — revoke ALL of the user's sessions AND token families (this is
    // also what a password change/reset calls). Closes the credential-change gap.
    [HttpPost("/account/logout-all"), ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutEverywhere()
    {
        var (_, session) = await CurrentSessionAsync();
        if (session is null) return Unauthorized();
        var sessionClients = await _sessions.GetUserSessionClientsAsync(session.UserId); // before revoke
        await _users.RevokeAllForUserAsync(session.UserId);   // tokens (all PPIDs) + all sessions
        await _bcl.NotifyAllSessionsAsync(session.UserId, sessionClients); // notify every RP, every device
        await _audit.WriteAsync("logout.all", session.UserId);
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

        // OIDC Session Management: the OP browser-state cookie (readable by the check_session_iframe
        // JS, hence NOT HttpOnly). It changes every login, so a new sid → "changed" at the RP.
        Response.Cookies.Append("opbs", sid, new CookieOptions
        {
            HttpOnly = false,
            SameSite = Request.IsHttps ? SameSiteMode.None : SameSiteMode.Lax, // None+Secure for the cross-site iframe in prod
            Secure = Request.IsHttps,
            MaxAge = TimeSpan.FromHours(8),
        });
    }
}
