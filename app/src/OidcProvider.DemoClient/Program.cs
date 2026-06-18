using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

// A minimal Relying Party that signs in through the OIDC provider (authorization code +
// PKCE, with PAR since the provider advertises it). Open http://localhost:5000.
var builder = WebApplication.CreateBuilder(args);
var authority = builder.Configuration["Oidc:Authority"] ?? "http://localhost:8081/";

// Persist DataProtection keys so a restart doesn't invalidate the correlation/auth cookies.
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Path.GetTempPath(), "oidc-rp-dpkeys")))
    .SetApplicationName("oidc-demo-rp");

// Sessions terminated by a back-channel logout_token (keyed by the id_token `sid`). A real RP
// would persist this; in-memory is fine for the demo. The cookie middleware consults it on every
// request so a logged-out session can't keep using its cookie.
var revokedSids = new ConcurrentDictionary<string, byte>();
var bclReceipts = new ConcurrentQueue<object>();

builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = "oidc";
    })
    .AddCookie(o =>
    {
        // Distinct name: OP and RP share host `localhost`, and cookies ignore port — the default
        // `.AspNetCore.Cookies` would collide and the RP login would clobber the OP session.
        o.Cookie.Name = ".DemoRP.Cookies";
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        // Back-channel logout enforcement: if this principal's session id was revoked by a
        // logout_token, drop the cookie so the user is bounced back to sign-in.
        o.Events.OnValidatePrincipal = ctx =>
        {
            var sid = ctx.Principal?.FindFirst("sid")?.Value;
            if (sid is not null && revokedSids.ContainsKey(sid))
            {
                ctx.RejectPrincipal();
                return ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
            return Task.CompletedTask;
        };
    })
    .AddOpenIdConnect("oidc", o =>
    {
        o.Authority = authority;                       // the OIDC provider
        o.ClientId = "demo-web";
        o.ClientSecret = "demo-secret-dev-only";
        o.ResponseType = "code";
        o.UsePkce = true;
        o.CallbackPath = "/callback";                  // registered redirect_uri
        o.SignedOutCallbackPath = "/signed-out";       // registered post_logout_redirect_uri
        o.Scope.Clear();
        o.Scope.Add("openid"); o.Scope.Add("email"); o.Scope.Add("profile"); o.Scope.Add("offline_access");
        o.GetClaimsFromUserInfoEndpoint = true;
        o.ClaimActions.MapJsonKey("sid", "sid"); // keep id_token `sid` so back-channel logout can match
        o.SaveTokens = true;
        o.RequireHttpsMetadata = false;                // local http authority
        // Local http: correlation/nonce cookies must not require Secure (else dropped → "Correlation failed").
        o.CorrelationCookie.SameSite = SameSiteMode.Lax;
        o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.NonceCookie.SameSite = SameSiteMode.Lax;
        o.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        // Handle a denied/failed sign-in gracefully instead of throwing (dev error page).
        o.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
        {
            OnAccessDenied = ctx =>
            {
                ctx.HandleResponse();
                ctx.Response.Redirect("/?msg=" + Uri.EscapeDataString("Sign-in was cancelled / consent denied."));
                return Task.CompletedTask;
            },
            OnRemoteFailure = ctx =>
            {
                ctx.HandleResponse();
                ctx.Response.Redirect("/?msg=" + Uri.EscapeDataString(ctx.Failure?.Message ?? "Sign-in failed."));
                return Task.CompletedTask;
            },
        };
    });

var app = builder.Build();
app.UseAuthentication();

// OIDC Back-Channel Logout 1.0 receiver. The OP POSTs a signed logout_token here; we validate it
// against the OP's JWKS and the BCL rules, then mark the session id revoked so the cookie dies.
app.MapPost("/backchannel-logout", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var token = form["logout_token"].ToString();
    if (string.IsNullOrEmpty(token))
        return Results.BadRequest("missing logout_token");

    using var http = new HttpClient();
    var conf = await http.GetFromJsonAsync<JsonElement>(
        $"{authority.TrimEnd('/')}/.well-known/openid-configuration");
    var jwks = new JsonWebKeySet(await http.GetStringAsync(conf.GetProperty("jwks_uri").GetString()));

    var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
    {
        ValidIssuer = conf.GetProperty("issuer").GetString(),
        ValidAudience = "demo-web",
        IssuerSigningKeys = jwks.GetSigningKeys(),
        ValidateLifetime = true,
    });
    if (!result.IsValid)
    {
        Console.WriteLine($"[BCL] logout_token rejected: {result.Exception?.GetType().Name}: {result.Exception?.Message}");
        return Results.BadRequest(new { error = "invalid_token", detail = result.Exception?.Message });
    }

    var jwt = (JsonWebToken)result.SecurityToken;
    // BCL §2.6 validation: events claim must carry the logout member, and a `nonce` MUST be absent
    // (its presence is the tell of an id_token being replayed as a logout_token).
    if (jwt.TryGetPayloadValue<string>("nonce", out _))
        return Results.BadRequest(new { error = "nonce_present" });
    if (!jwt.TryGetPayloadValue<JsonElement>("events", out var events) ||
        !events.TryGetProperty("http://schemas.openid.net/event/backchannel-logout", out _))
        return Results.BadRequest(new { error = "missing_logout_event" });

    var sid = jwt.TryGetPayloadValue<string>("sid", out var s) ? s : null;
    var sub = jwt.TryGetPayloadValue<string>("sub", out var su) ? su : null;
    if (sid is not null) revokedSids[sid] = 1;
    bclReceipts.Enqueue(new { received = true, sub, sid, aud = jwt.Audiences.FirstOrDefault() });
    return Results.Ok(); // 200 → OP records success
});

// OIDC Front-Channel Logout 1.0 receiver. Loaded by the OP in a hidden iframe at end-session;
// the `sid` query param (FCL session_required) identifies the session to terminate — which works
// even when third-party-cookie rules would hide our own cookie inside the cross-site iframe.
app.MapGet("/frontchannel-logout", (string? iss, string? sid) =>
{
    if (iss is not null && iss.TrimEnd('/') != authority.TrimEnd('/'))
        return Results.BadRequest("iss mismatch");
    if (sid is not null) revokedSids[sid] = 1;
    bclReceipts.Enqueue(new { channel = "front", received = true, iss, sid });
    return Results.Content("<!doctype html>logged out", "text/html");
});

// Inspection endpoint for the demo/tests: what logout signals have we accepted?
app.MapGet("/backchannel-events", () => Results.Json(bclReceipts.ToArray()));

app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, ["oidc"]));
app.MapPost("/logout", () => Results.SignOut(   // RP-initiated logout (clears RP + provider session)
    new AuthenticationProperties { RedirectUri = "/" },
    [CookieAuthenticationDefaults.AuthenticationScheme, "oidc"]));

app.MapGet("/", async ctx =>
{
    ctx.Response.ContentType = "text/html; charset=utf-8";
    var sb = new StringBuilder("<!doctype html><meta charset=utf-8><title>OIDC Demo RP</title>");
    sb.Append("<style>body{font:15px system-ui;max-width:46rem;margin:3rem auto;padding:0 1rem}" +
              "li{margin:.15rem 0}code{background:#8881;padding:.1rem .3rem}</style>");
    sb.Append("<h1>OIDC Demo Relying Party</h1>");
    if (ctx.Request.Query["msg"].ToString() is { Length: > 0 } msg)
        sb.Append($"<p style='color:#b00;border:1px solid #b008;padding:.5rem'>⚠ {WebUtility.HtmlEncode(msg)}</p>");
    if (ctx.User.Identity?.IsAuthenticated != true)
    {
        sb.Append("<p>You are not signed in.</p><p><a href=\"/login\">▶ Sign in with the OIDC Provider</a></p>");
        sb.Append("<p style=color:#666>On the provider login page you can use a password, TOTP, " +
                  "the <b>Log in with Loopback IdP</b> federation button, or consent — all flow back here.</p>");
    }
    else
    {
        sb.Append("<h2>✅ Signed in</h2><h3>Claims (from id_token + userinfo)</h3><ul>");
        foreach (var c in ctx.User.Claims.OrderBy(c => c.Type))
            sb.Append($"<li><code>{WebUtility.HtmlEncode(c.Type)}</code> = {WebUtility.HtmlEncode(c.Value)}</li>");
        sb.Append("</ul><h3>Tokens</h3><ul>");
        foreach (var t in new[] { "access_token", "id_token", "refresh_token" })
        {
            var v = await ctx.GetTokenAsync(t);
            sb.Append($"<li><code>{t}</code>: {(v is null ? "—" : WebUtility.HtmlEncode(v[..Math.Min(48, v.Length)]) + "…")}</li>");
        }
        sb.Append("</ul><form method=post action=/logout><button>Log out (RP-initiated)</button></form>");
    }
    await ctx.Response.WriteAsync(sb.ToString());
});

app.Run();
