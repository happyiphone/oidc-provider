using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OidcProvider.Api.Controllers;

// Dynamic Client Registration (RFC 7591). Gated behind an initial access token so it is
// NOT open registration (threat T8). Creates an OpenIddict application from the submitted
// metadata and returns the client_id/secret once.
[ApiController]
public sealed class RegisterController : Controller
{
    private static readonly HashSet<string> SupportedScopes =
        new() { "openid", "email", "profile", "offline_access", "api" };

    private readonly IOpenIddictApplicationManager _apps;
    private readonly IConfiguration _cfg;
    public RegisterController(IOpenIddictApplicationManager apps, IConfiguration cfg)
        => (_apps, _cfg) = (apps, cfg);

    [HttpPost("/register"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Register()
    {
        // Initial access token gate (RFC 7591 §3 — restricted registration).
        var iat = _cfg["Oidc:Registration:InitialAccessToken"];
        var presented = Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(iat) ||
            !presented.Equals("Bearer " + iat, StringComparison.Ordinal))
            return Unauthorized();

        JsonElement body;
        try { body = await JsonSerializer.DeserializeAsync<JsonElement>(Request.Body); }
        catch { return Error("invalid_client_metadata", "Malformed JSON."); }

        var grantTypes = StrArray(body, "grant_types") is { Length: > 0 } g ? g : new[] { "authorization_code" };
        var redirectUris = StrArray(body, "redirect_uris") ?? Array.Empty<string>();
        var authMethod = Str(body, "token_endpoint_auth_method") ?? "client_secret_basic";
        var requestedScopes = (Str(body, "scope") ?? "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(SupportedScopes.Contains).ToArray();

        if (grantTypes.Contains("authorization_code") && redirectUris.Length == 0)
            return Error("invalid_redirect_uri", "authorization_code requires at least one redirect_uri.");
        foreach (var u in redirectUris)
            if (!Uri.TryCreate(u, UriKind.Absolute, out _))
                return Error("invalid_redirect_uri", $"Not an absolute URI: {u}");

        var isPublic = authMethod == "none";
        var clientId = "dyn-" + Guid.NewGuid().ToString("n");
        var clientSecret = isPublic ? null : B64(RandomNumberGenerator.GetBytes(32));

        var desc = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            ClientType = isPublic ? ClientTypes.Public : ClientTypes.Confidential,
            ConsentType = ConsentTypes.Explicit,
            DisplayName = Str(body, "client_name"),
        };
        desc.Permissions.Add(Permissions.Endpoints.Token);
        foreach (var u in redirectUris) desc.RedirectUris.Add(new Uri(u));
        if (grantTypes.Contains("authorization_code"))
        {
            desc.Permissions.Add(Permissions.Endpoints.Authorization);
            desc.Permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            desc.Permissions.Add(Permissions.ResponseTypes.Code);
            desc.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange); // PKCE (ADR-0011)
        }
        if (grantTypes.Contains("refresh_token")) desc.Permissions.Add(Permissions.GrantTypes.RefreshToken);
        if (grantTypes.Contains("client_credentials")) desc.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
        foreach (var s in requestedScopes) desc.Permissions.Add(Permissions.Prefixes.Scope + s);

        await _apps.CreateAsync(desc);

        // RFC 7591 §3.2.1 response (client_secret returned once, at registration).
        return Created(string.Empty, new Dictionary<string, object?>
        {
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["client_id_issued_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["client_secret_expires_at"] = 0,
            ["token_endpoint_auth_method"] = authMethod,
            ["grant_types"] = grantTypes,
            ["redirect_uris"] = redirectUris,
            ["scope"] = string.Join(' ', requestedScopes),
            ["client_name"] = Str(body, "client_name"),
        });
    }

    private IActionResult Error(string code, string desc) =>
        BadRequest(new { error = code, error_description = desc });

    private static string? Str(JsonElement e, string n) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;
    private static string[]? StrArray(JsonElement e, string n) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray() : null;
    private static string B64(byte[] b) => OidcProvider.Core.Base64UrlText.Encode(b);
}
