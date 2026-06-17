using System.Net;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

// A minimal Relying Party that signs in through the OIDC provider (authorization code +
// PKCE, with PAR since the provider advertises it). Open http://localhost:5000.
var builder = WebApplication.CreateBuilder(args);
var authority = builder.Configuration["Oidc:Authority"] ?? "http://localhost:8081/";

builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = "oidc";
    })
    .AddCookie(o => o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest)
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
        o.SaveTokens = true;
        o.RequireHttpsMetadata = false;                // local http authority
    });

var app = builder.Build();
app.UseAuthentication();

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
