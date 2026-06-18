using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OidcProvider.Core.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Controllers;

// RFC 8628 end-user verification endpoint. The device hit POST /device to get a user_code; the
// user comes here (on a phone/laptop), authenticates, enters/confirms the code, and approves.
// Approval = SignIn on the OpenIddict scheme, which binds the user to the pending device_code so
// the device's token poll succeeds. OpenIddict already validated the request before passthrough.
public sealed class DeviceController : Controller
{
    private readonly IUserSession _sessions;
    private readonly IUserService _users;
    private readonly IPairwiseSubjects _ppid;
    private readonly IAntiforgery _antiforgery;
    private readonly IAuditLog _audit;

    public DeviceController(IUserSession sessions, IUserService users, IPairwiseSubjects ppid,
        IAntiforgery antiforgery, IAuditLog audit)
        => (_sessions, _users, _ppid, _antiforgery, _audit) = (sessions, users, ppid, antiforgery, audit);

    [HttpGet("/device/verify")]
    public async Task<IActionResult> Verify()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        if (await RequireSessionAsync() is null) return Challenge();

        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        var userCode = WebUtility.HtmlEncode(request?.UserCode ?? "");
        var af = $"<input type=hidden name=__RequestVerificationToken value=\"{tokens.RequestToken}\" />";

        // No code yet → ask for it (GET re-enters with the code so OpenIddict can validate it).
        var inner = string.IsNullOrEmpty(userCode)
            ? "<form method=get action=/device/verify>Enter the code shown on your device:<br>" +
              "<input name=user_code autofocus /> <button>Continue</button></form>"
            // Code present + validated → confirm.
            : $"<p>Authorize this device for <b>{User.Identity?.Name ?? "your account"}</b>?</p>" +
              $"<form method=post action=/device/verify>{af}" +
              $"<input type=hidden name=user_code value=\"{userCode}\" />" +
              "<button name=submit value=accept>Allow</button> " +
              "<button name=submit value=deny>Deny</button></form>";

        return Content("<!doctype html><meta charset=utf-8><title>Device authorization</title>" +
                       "<h1>Device authorization</h1>" + inner, "text/html");
    }

    [HttpPost("/device/verify")]
    public async Task<IActionResult> VerifyAccept([FromForm] string? submit)
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        var session = await RequireSessionAsync();
        if (session is null) return Challenge();

        try { await _antiforgery.ValidateRequestAsync(HttpContext); }
        catch (AntiforgeryValidationException) { return BadRequest("Invalid antiforgery token."); }

        if (submit != "accept")
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User denied the device.",
                }));

        var user = await _users.GetAsync(session.UserId);
        if (user is null) return Challenge();
        var sid = User.FindFirst("sid")!.Value;

        // The scopes (and client) the device asked for live on the device-code principal that
        // OpenIddict bound to this user_code — authenticate the server scheme to recover them.
        var deviceGrant = (await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
        var scopes = deviceGrant?.GetScopes() ?? System.Collections.Immutable.ImmutableArray<string>.Empty;
        var sector = deviceGrant?.GetClaim(Claims.ClientId) ?? request?.ClientId ?? "device";

        var identity = new ClaimsIdentity(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, await _ppid.ForAsync(user.Id, sector));
        identity.SetClaim(Claims.Email, user.Email);
        identity.SetClaim(Claims.EmailVerified, user.EmailVerified);
        identity.SetClaim("sid", sid);
        identity.SetScopes(scopes);
        identity.SetDestinations(OidcDestinations.For);

        await _audit.WriteAsync("device.approved", user.Id, request?.ClientId);
        // OpenIddict marks the matching device_code authorized; the device's token poll now succeeds.
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<UserSessionData?> RequireSessionAsync()
        => User.FindFirst("sid")?.Value is { } sid ? await _sessions.GetAsync(sid) : null;

    private new IActionResult Challenge() => base.Challenge(
        authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
        properties: new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString });
}
