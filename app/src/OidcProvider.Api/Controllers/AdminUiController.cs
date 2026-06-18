using System.Net;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace OidcProvider.Api.Controllers;

// Minimal browser admin console for clients (the JSON admin API in AdminClientsController is
// headless-only). Gated by the same admin key, entered once via a form that sets an HttpOnly
// cookie. PROD should put this behind real admin SSO + RBAC, not a shared key — noted in the UI.
public sealed class AdminUiController : Controller
{
    private readonly IOpenIddictApplicationManager _apps;
    private readonly IConfiguration _cfg;
    private readonly IAntiforgery _antiforgery;
    public AdminUiController(IOpenIddictApplicationManager apps, IConfiguration cfg, IAntiforgery antiforgery)
        => (_apps, _cfg, _antiforgery) = (apps, cfg, antiforgery);

    private const string Cookie = "admin_key";
    private bool Authed()
    {
        var key = _cfg["Oidc:Admin:ApiKey"];
        return !string.IsNullOrEmpty(key) &&
               Request.Cookies.TryGetValue(Cookie, out var c) && c == key;
    }

    [HttpGet("/admin/ui")]
    public async Task<IActionResult> Index()
    {
        if (!Authed())
        {
            var t = _antiforgery.GetAndStoreTokens(HttpContext);
            return Html("<h1>Admin sign-in</h1>" +
                "<form method=post action=/admin/ui/login>" +
                $"<input type=hidden name=__RequestVerificationToken value=\"{t.RequestToken}\" />" +
                "Admin API key: <input type=password name=key autofocus /> <button>Sign in</button></form>" +
                "<p style=color:#888>Dev console. Production should use admin SSO + RBAC, not a shared key.</p>");
        }

        var t2 = _antiforgery.GetAndStoreTokens(HttpContext);
        var sb = new StringBuilder("<h1>Clients</h1><table border=1 cellpadding=6 cellspacing=0>" +
            "<tr><th>client_id</th><th>name</th><th>type</th><th>backchannel_logout_uri</th><th></th></tr>");
        await foreach (var app in _apps.ListAsync())
        {
            var id = await _apps.GetClientIdAsync(app) ?? "";
            var name = await _apps.GetDisplayNameAsync(app) ?? "";
            var type = await _apps.GetClientTypeAsync(app) ?? "";
            var props = await _apps.GetPropertiesAsync(app);
            var bcl = props.TryGetValue("backchannel_logout_uri", out var b) ? b.GetString() ?? "" : "";
            sb.Append($"<tr><td><code>{E(id)}</code></td><td>{E(name)}</td><td>{E(type)}</td><td>{E(bcl)}</td>" +
                "<td><form method=post action=/admin/ui/delete onsubmit=\"return confirm('Delete " + E(id) + "?')\">" +
                $"<input type=hidden name=__RequestVerificationToken value=\"{t2.RequestToken}\" />" +
                $"<input type=hidden name=clientId value=\"{E(id)}\" /><button>Delete</button></form></td></tr>");
        }
        sb.Append("</table><form method=post action=/admin/ui/logout style=margin-top:1rem>" +
            $"<input type=hidden name=__RequestVerificationToken value=\"{t2.RequestToken}\" /><button>Sign out</button></form>");
        return Html(sb.ToString());
    }

    [HttpPost("/admin/ui/login"), ValidateAntiForgeryToken]
    public IActionResult Login([FromForm] string? key)
    {
        var expected = _cfg["Oidc:Admin:ApiKey"];
        if (string.IsNullOrEmpty(expected) || key != expected)
            return Html("<p>Invalid key.</p><p><a href=/admin/ui>Back</a></p>");
        Response.Cookies.Append(Cookie, key!, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = !HttpContext.Request.IsHttps ? false : true, // Secure on https; dev http allowed
            MaxAge = TimeSpan.FromHours(8),
        });
        return Redirect("/admin/ui");
    }

    [HttpPost("/admin/ui/delete"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete([FromForm] string? clientId)
    {
        if (!Authed()) return Unauthorized();
        if (await _apps.FindByClientIdAsync(clientId ?? "") is { } app)
            await _apps.DeleteAsync(app);
        return Redirect("/admin/ui");
    }

    [HttpPost("/admin/ui/logout"), ValidateAntiForgeryToken]
    public IActionResult Logout()
    {
        Response.Cookies.Delete(Cookie);
        return Redirect("/admin/ui");
    }

    private static string E(string s) => WebUtility.HtmlEncode(s);
    private IActionResult Html(string body) => Content(
        "<!doctype html><meta charset=utf-8><title>Admin</title>" +
        "<style>body{font:15px system-ui;max-width:60rem;margin:2rem auto;padding:0 1rem}" +
        "code{background:#8881;padding:.1rem .3rem}table{border-collapse:collapse}</style>" + body,
        "text/html");
}
