using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace OidcProvider.Tests;

// In-process integration tests = our automated conformance/abuse gate (run in CI).
// Boots the real app via WebApplicationFactory against a dedicated test DB + Redis.
// Mirrors docs/oidc-provider/abuse-case-tests.md (AC-*) and the happy paths.
public sealed class OidcAppFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(Environments.Development);
        builder.UseSetting("ConnectionStrings:Postgres",
            Environment.GetEnvironmentVariable("TEST_PG")
            ?? "Host=localhost;Port=5433;Database=oidc_test;Username=oidc;Password=oidc_dev_only");
        builder.UseSetting("ConnectionStrings:Redis",
            Environment.GetEnvironmentVariable("TEST_REDIS") ?? "localhost:6380");
        builder.UseSetting("Oidc:Issuer", "http://localhost/");
        builder.UseSetting("Oidc:RefreshReuseLeewaySeconds", "0"); // detect reuse immediately
        builder.UseSetting("Oidc:Signing:Mode", "Dev");
    }
}

public sealed class IntegrationTests : IClassFixture<OidcAppFactory>
{
    private readonly OidcAppFactory _factory;
    private const string RedirectUri = "http://localhost:5000/callback";

    public IntegrationTests(OidcAppFactory factory) => _factory = factory;

    private HttpClient NewClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    // ---------- discovery / jwks ----------

    [Fact]
    public async Task Discovery_advertises_core_endpoints()
    {
        var json = await (await NewClient().GetAsync("/.well-known/openid-configuration"))
            .Content.ReadAsStringAsync();
        using var d = JsonDocument.Parse(json);
        var r = d.RootElement;
        Assert.EndsWith("/authorize", r.GetProperty("authorization_endpoint").GetString());
        Assert.EndsWith("/token", r.GetProperty("token_endpoint").GetString());
        Assert.Contains("S256", r.GetProperty("code_challenge_methods_supported").EnumerateArray()
            .Select(e => e.GetString()));
        Assert.Contains("pushed_authorization_request_endpoint", json); // PAR (RFC 9126)
    }

    [Fact]
    public async Task Jwks_publishes_es256_key()
    {
        var json = await (await NewClient().GetAsync("/.well-known/jwks")).Content.ReadAsStringAsync();
        Assert.Contains("\"kty\":\"EC\"", json.Replace(" ", ""));
        Assert.Contains("ES256", json);
    }

    // ---------- happy paths ----------

    [Fact]
    public async Task ClientCredentials_issues_access_token()
    {
        var res = await NewClient().PostAsync("/token", Form(new()
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = "api",
            ["client_id"] = "svc-loadtest",
            ["client_secret"] = "svc-secret-dev-only",
        }));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("access_token", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AuthCode_pkce_happy_path_yields_tokens_and_userinfo()
    {
        var c = NewClient();
        var (verifier, challenge) = Pkce();
        await LoginAsync(c, "alice", "password123!");
        var code = await GetCodeAsync(c, "openid email", challenge, nonce: "n1");
        var tok = await ExchangeCodeAsync(c, code, verifier);

        Assert.True(tok.TryGetProperty("access_token", out _));
        Assert.True(tok.TryGetProperty("id_token", out var idt));
        var claims = DecodeJwt(idt.GetString()!);
        Assert.Equal("demo-web", claims.GetProperty("aud").GetString());
        Assert.Equal("n1", claims.GetProperty("nonce").GetString());
        var sub = claims.GetProperty("sub").GetString();

        // userinfo sub must equal the (pairwise) id_token sub
        var ui = c.SendAsync(Bearer("/userinfo", tok.GetProperty("access_token").GetString()!)).Result;
        var uiJson = JsonDocument.Parse(ui.Content.ReadAsStringAsync().Result).RootElement;
        Assert.Equal(sub, uiJson.GetProperty("sub").GetString());
    }

    // ---------- abuse cases (AC-*) ----------

    [Fact] // AC-T1-1
    public async Task Reused_authorization_code_is_rejected()
    {
        var c = NewClient();
        var (verifier, challenge) = Pkce();
        await LoginAsync(c, "alice", "password123!");
        var code = await GetCodeAsync(c, "openid", challenge, "r1");
        var first = await ExchangeCodeRawAsync(c, code, verifier);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var second = await ExchangeCodeRawAsync(c, code, verifier);
        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
        Assert.Contains("invalid_grant", await second.Content.ReadAsStringAsync());
    }

    [Fact] // AC-T11-1
    public async Task Missing_pkce_challenge_is_rejected()
    {
        var c = NewClient();
        await LoginAsync(c, "alice", "password123!");
        var res = await c.GetAsync($"/authorize?client_id=demo-web&response_type=code" +
            $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}&scope=openid&state=s");
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact] // AC-T11-3
    public async Task Wrong_pkce_verifier_is_rejected()
    {
        var c = NewClient();
        var (_, challenge) = Pkce();
        await LoginAsync(c, "alice", "password123!");
        var code = await GetCodeAsync(c, "openid", challenge, "w1");
        var res = await ExchangeCodeRawAsync(c, code, "wrong-verifier-value-not-matching-challenge-xxxx");
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Contains("invalid_grant", await res.Content.ReadAsStringAsync());
    }

    [Fact] // AC-T2-1
    public async Task Unregistered_redirect_uri_does_not_redirect()
    {
        var c = NewClient();
        var (_, challenge) = Pkce();
        await LoginAsync(c, "alice", "password123!");
        var res = await c.GetAsync($"/authorize?client_id=demo-web&response_type=code" +
            $"&redirect_uri={Uri.EscapeDataString("http://evil.example/cb")}&scope=openid&state=s" +
            $"&code_challenge={challenge}&code_challenge_method=S256");
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Null(res.Headers.Location); // must NOT 302 to the attacker
    }

    [Fact] // AC-T4-1 / AC-T4-2
    public async Task Refresh_token_reuse_revokes_the_family()
    {
        var c = NewClient();
        var (verifier, challenge) = Pkce();
        await LoginAsync(c, "alice", "password123!");
        var code = await GetCodeAsync(c, "openid email offline_access", challenge, "rt");
        var tok = await ExchangeCodeAsync(c, code, verifier);
        var rt1 = tok.GetProperty("refresh_token").GetString()!;

        var r2 = await RedeemRefreshAsync(c, rt1);
        Assert.Equal(HttpStatusCode.OK, r2.status);
        var rt2 = r2.json!.Value.GetProperty("refresh_token").GetString()!;
        Assert.NotEqual(rt1, rt2);                       // rotation

        var reuse = await RedeemRefreshAsync(c, rt1);    // reuse rotated-out token
        Assert.Equal(HttpStatusCode.BadRequest, reuse.status);

        var rt2After = await RedeemRefreshAsync(c, rt2);  // family revoked → rt2 also dead
        Assert.Equal(HttpStatusCode.BadRequest, rt2After.status);
    }

    // ---------- helpers ----------

    private static (string verifier, string challenge) Pkce()
    {
        var verifier = B64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static async Task LoginAsync(HttpClient c, string user, string pwd)
    {
        var page = await c.GetStringAsync("/account/login");
        var token = AntiforgeryToken(page);
        var res = await c.PostAsync("/account/login", Form(new()
        {
            ["username"] = user, ["password"] = pwd, ["returnUrl"] = "/",
            ["__RequestVerificationToken"] = token,
        }));
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
    }

    private async Task<string> GetCodeAsync(HttpClient c, string scope, string challenge, string nonce)
    {
        var q = $"client_id=demo-web&response_type=code&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                $"&scope={Uri.EscapeDataString(scope)}&state=s&nonce={nonce}" +
                $"&code_challenge={challenge}&code_challenge_method=S256";
        var res = await c.GetAsync($"/authorize?{q}");
        if (res.StatusCode == HttpStatusCode.Redirect)               // consent already granted
            return CodeFromLocation(res.Headers.Location!);

        // consent page → accept with antiforgery token
        var token = AntiforgeryToken(await res.Content.ReadAsStringAsync());
        var form = ParseQuery(q);
        form["submit"] = "accept";
        form["__RequestVerificationToken"] = token;
        var post = await c.PostAsync("/authorize", Form(form));
        Assert.Equal(HttpStatusCode.Redirect, post.StatusCode);
        return CodeFromLocation(post.Headers.Location!);
    }

    private async Task<HttpResponseMessage> ExchangeCodeRawAsync(HttpClient c, string code, string verifier)
        => await c.PostAsync("/token", Form(new()
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = verifier, ["client_id"] = "demo-web", ["client_secret"] = "demo-secret-dev-only",
        }));

    private async Task<JsonElement> ExchangeCodeAsync(HttpClient c, string code, string verifier)
    {
        var res = await ExchangeCodeRawAsync(c, code, verifier);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        return JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    private async Task<(HttpStatusCode status, JsonElement? json)> RedeemRefreshAsync(HttpClient c, string rt)
    {
        var res = await c.PostAsync("/token", Form(new()
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = rt,
            ["client_id"] = "demo-web", ["client_secret"] = "demo-secret-dev-only",
        }));
        if (res.StatusCode != HttpStatusCode.OK) return (res.StatusCode, null);
        return (res.StatusCode, JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.Clone());
    }

    private static HttpRequestMessage Bearer(string url, string token)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new("Bearer", token);
        return req;
    }

    private static FormUrlEncodedContent Form(Dictionary<string, string> d) => new(d);

    private static Dictionary<string, string> ParseQuery(string q) =>
        q.Split('&').Select(p => p.Split('=', 2))
         .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));

    private static string CodeFromLocation(Uri loc)
    {
        foreach (var part in loc.Query.TrimStart('?').Split('&'))
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 2 && Uri.UnescapeDataString(kv[0]) == "code")
                return Uri.UnescapeDataString(kv[1]);
        }
        throw new Xunit.Sdk.XunitException($"no code in {loc}");
    }

    private static string AntiforgeryToken(string html) =>
        Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;

    private static JsonElement DecodeJwt(string jwt)
    {
        var payload = jwt.Split('.')[1];
        payload = payload.Replace('-', '+').Replace('_', '/').PadRight((payload.Length + 3) / 4 * 4, '=');
        return JsonDocument.Parse(Convert.FromBase64String(payload)).RootElement.Clone();
    }

    private static string B64Url(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
