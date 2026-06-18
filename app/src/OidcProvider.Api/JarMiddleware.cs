using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace OidcProvider.Api;

// The two RFC 9101 envelopes, supported around OpenIddict (which has neither natively) WITHOUT
// reimplementing the protocol core — OpenIddict still does all OAuth logic in between:
//   • JAR  (request side):  validate a signed `request` object → expand it into the query.
//   • JARM (response side): if the client asked for `response_mode=*.jwt`, wrap the authorization
//                           response parameters in a signed JWT (`response=<JWT>`).
// JARM intent is captured at the initial request (keyed by `state` + the client's redirect_uri) so
// it survives the login/consent round-trips, and is applied only to the final response that
// actually targets the redirect_uri. Scoped to /authorize.
public sealed class JarMiddleware
{
    private static readonly HashSet<string> JwtMeta =
        new(StringComparer.Ordinal) { "iss", "aud", "exp", "iat", "nbf", "jti", "request", "request_uri" };

    // state -> (base response mode, client redirect_uri, unix-seconds). Short-lived, in-process.
    private sealed record JarmIntent(string BaseMode, string RedirectUri, string ClientId, long Ts);
    private static readonly ConcurrentDictionary<string, JarmIntent> JarmByState = new();

    private readonly RequestDelegate _next;
    private readonly string _issuer;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _server;
    public JarMiddleware(RequestDelegate next, IConfiguration cfg, IOptionsMonitor<OpenIddictServerOptions> server)
        => (_next, _issuer, _server) = (next, cfg["Oidc:Issuer"] ?? "", server);

    public async Task Invoke(HttpContext ctx)
    {
        if (ctx.Request.Query.ContainsKey("request") && !await ExpandJarAsync(ctx))
            return; // JAR present but invalid → 400 already written

        // JARM request detection (query reflects both plain JARM and a JAR-expanded request).
        var rm = ctx.Request.Query["response_mode"].ToString();
        if (rm is "jwt" or "query.jwt" or "fragment.jwt" or "form_post.jwt")
        {
            var baseMode = rm == "jwt" ? "query" : rm[..^4];
            var state = ctx.Request.Query["state"].ToString();
            var redirectUri = ctx.Request.Query["redirect_uri"].ToString();
            var clientId = ctx.Request.Query["client_id"].ToString();
            if (!string.IsNullOrEmpty(state))
                JarmByState[state] = new JarmIntent(baseMode, redirectUri, clientId,
                    DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            RewriteQuery(ctx, q => q["response_mode"] = baseMode); // OpenIddict accepts the base mode
            Purge();
        }

        // Buffer so we can recognise + wrap the final authorization response (which may be emitted on
        // the consent POST, where request params live in the body — so we key off the OUTPUT instead).
        var original = ctx.Response.Body;
        using var buffer = new MemoryStream();
        ctx.Response.Body = buffer;
        try { await _next(ctx); }
        finally { ctx.Response.Body = original; }

        if (!await TryWrapJarmAsync(ctx, buffer, original))
        {
            buffer.Position = 0;
            await buffer.CopyToAsync(original); // not a JARM response → pass through untouched
        }
    }

    // Returns true if it recognised + wrote a JARM response; false to pass through.
    private async Task<bool> TryWrapJarmAsync(HttpContext ctx, MemoryStream buffer, Stream original)
    {
        // (a) redirect (query/fragment modes)
        if (ctx.Response.StatusCode is >= 300 and < 400 &&
            ctx.Response.Headers.Location.ToString() is { Length: > 0 } location)
        {
            var cut = location.IndexOfAny(new[] { '?', '#' });
            if (cut < 0) return false;
            var (uri, rest) = (location[..cut], location[(cut + 1)..]);
            var prms = ParseKv(rest);
            if (!prms.TryGetValue("state", out var st) || !JarmByState.TryGetValue(st, out var intent)) return false;
            if (!location.StartsWith(intent.RedirectUri, StringComparison.Ordinal)) return false; // only the real response
            JarmByState.TryRemove(st, out _);
            var sep = intent.BaseMode == "fragment" ? '#' : '?';
            ctx.Response.Headers.Location = $"{uri}{sep}response={Uri.EscapeDataString(Sign(prms, intent.ClientId))}";
            ctx.Response.ContentLength = 0;
            return true;
        }
        // (b) form_post (200 HTML auto-submit form)
        if (ctx.Response.StatusCode == 200)
        {
            var html = Encoding.UTF8.GetString(buffer.ToArray());
            var action = Match(html, "action=\"([^\"]+)\"");
            if (action.Length == 0) return false;
            var fields = ParseHiddenInputs(html);
            if (!fields.TryGetValue("state", out var st) || !JarmByState.TryGetValue(st, out var intent)) return false;
            if (!action.StartsWith(intent.RedirectUri, StringComparison.Ordinal)) return false; // not the response form
            JarmByState.TryRemove(st, out _);
            var jwt = Sign(fields, intent.ClientId);
            var body = "<!doctype html><html><body><form method=post action=\"" + System.Net.WebUtility.HtmlEncode(action) +
                       "\"><input type=hidden name=response value=\"" + System.Net.WebUtility.HtmlEncode(jwt) +
                       "\" /></form><script>document.forms[0].submit()</script></body></html>";
            var bytes = Encoding.UTF8.GetBytes(body);
            ctx.Response.ContentLength = bytes.Length;
            ctx.Response.ContentType = "text/html;charset=UTF-8";
            await original.WriteAsync(bytes);
            return true;
        }
        return false;
    }

    // ---- JAR ---------------------------------------------------------------
    private async Task<bool> ExpandJarAsync(HttpContext ctx)
    {
        var jar = ctx.Request.Query["request"].ToString();
        var handler = new JsonWebTokenHandler();
        string clientId;
        try
        {
            var unverified = handler.ReadJsonWebToken(jar);
            clientId = ctx.Request.Query["client_id"].FirstOrDefault()
                ?? (unverified.TryGetPayloadValue<string>("client_id", out var c) ? c : "");
        }
        catch { await Reject(ctx, "invalid_request_object", "Malformed request object."); return false; }
        if (string.IsNullOrEmpty(clientId)) { await Reject(ctx, "invalid_request", "Missing client_id."); return false; }

        var apps = ctx.RequestServices.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await apps.FindByClientIdAsync(clientId);
        if (app is null) { await Reject(ctx, "invalid_client", "Unknown client."); return false; }
        var props = await apps.GetPropertiesAsync(app);
        if (!props.TryGetValue("jwks", out var jwksEl))
        { await Reject(ctx, "invalid_request_object", "Client has no registered keys for JAR."); return false; }

        JsonWebKeySet jwks;
        try { jwks = new JsonWebKeySet(jwksEl.GetString()); }
        catch { await Reject(ctx, "invalid_request_object", "Client JWKS is unreadable."); return false; }

        var result = await handler.ValidateTokenAsync(jar, new TokenValidationParameters
        {
            ValidIssuer = clientId,
            ValidAudiences = new[] { _issuer, _issuer.TrimEnd('/') },
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidateLifetime = true,
        });
        if (!result.IsValid)
        { await Reject(ctx, "invalid_request_object", "Request object signature/claims invalid."); return false; }

        var jwt = (JsonWebToken)result.SecurityToken;
        var merged = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var kv in ctx.Request.Query) if (kv.Key != "request") merged[kv.Key] = kv.Value;
        using (var doc = JsonDocument.Parse(B64UrlToText(jwt.EncodedPayload)))
            foreach (var p in doc.RootElement.EnumerateObject())
                if (!JwtMeta.Contains(p.Name) && p.Value.ValueKind == JsonValueKind.String)
                    merged[p.Name] = p.Value.GetString();
        merged["client_id"] = clientId;
        ctx.Request.QueryString = QueryString.Create(merged!);
        return true;
    }

    // ---- JARM signing ------------------------------------------------------
    private string Sign(IDictionary<string, string> parameters, string clientId)
    {
        var creds = _server.CurrentValue.SigningCredentials.First();
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object> { ["aud"] = clientId };
        foreach (var (k, v) in parameters) if (k != "iss") claims[k] = v; // code, state, error, …
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            IssuedAt = now.UtcDateTime,
            Expires = now.AddMinutes(5).UtcDateTime,
            SigningCredentials = creds,
            Claims = claims,
        });
    }

    // ---- helpers -----------------------------------------------------------
    private static void Purge()
    {
        if (JarmByState.Count < 256) return;
        var cutoff = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600;
        foreach (var kv in JarmByState) if (kv.Value.Ts < cutoff) JarmByState.TryRemove(kv.Key, out _);
    }

    private static void RewriteQuery(HttpContext ctx, Action<Dictionary<string, string?>> mutate)
    {
        var q = ctx.Request.Query.ToDictionary(k => k.Key, v => (string?)v.Value.ToString());
        mutate(q);
        ctx.Request.QueryString = QueryString.Create(q!);
    }

    private static Dictionary<string, string> ParseKv(string s) =>
        s.Split('&', StringSplitOptions.RemoveEmptyEntries)
         .Select(p => p.Split('=', 2))
         .ToDictionary(a => Uri.UnescapeDataString(a[0]), a => a.Length > 1 ? Uri.UnescapeDataString(a[1]) : "");

    private static Dictionary<string, string> ParseHiddenInputs(string html)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match m in Regex.Matches(html, "name=\"([^\"]+)\"\\s+value=\"([^\"]*)\""))
            d[m.Groups[1].Value] = System.Net.WebUtility.HtmlDecode(m.Groups[2].Value);
        return d;
    }

    private static string Match(string s, string pattern)
    {
        var m = Regex.Match(s, pattern);
        return m.Success ? System.Net.WebUtility.HtmlDecode(m.Groups[1].Value) : "";
    }

    private static string B64UrlToText(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/'); s += new string('=', (4 - s.Length % 4) % 4);
        return Encoding.UTF8.GetString(Convert.FromBase64String(s));
    }

    private static async Task Reject(HttpContext ctx, string error, string desc)
    {
        ctx.Response.StatusCode = 400;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(new { error, error_description = desc }));
    }
}
