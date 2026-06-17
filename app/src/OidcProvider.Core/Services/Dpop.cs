using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StackExchange.Redis;

namespace OidcProvider.Core.Services;

// DPoP (RFC 9449) proof validation. A DPoP proof is a JWT:
//   header  = { typ:"dpop+jwt", alg:"ES256", jwk:{public EC P-256 key} }
//   payload = { htm, htu, iat, jti, ath? }
// Validates the proof and returns the JWK SHA-256 thumbprint (jkt, RFC 7638) the caller
// binds into the token's `cnf` claim — making the token sender-constrained.
public interface IDpopValidator
{
    // Returns the jkt on success, or null if the proof is invalid/replayed.
    Task<string?> ValidateAsync(string proof, string htm, string htu,
        string? accessToken = null, CancellationToken ct = default);
}

public sealed class DpopValidator : IDpopValidator
{
    private readonly IDatabase _redis;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1); // iat freshness + jti TTL
    public DpopValidator(IConnectionMultiplexer mux) => _redis = mux.GetDatabase();

    public async Task<string?> ValidateAsync(string proof, string htm, string htu,
        string? accessToken = null, CancellationToken ct = default)
    {
        var parts = proof.Split('.');
        if (parts.Length != 3) return null;
        JsonElement header, payload;
        try
        {
            header = JsonDocument.Parse(B64.Decode(parts[0])).RootElement;
            payload = JsonDocument.Parse(B64.Decode(parts[1])).RootElement;
        }
        catch { return null; }

        // 1. Header: typ, alg, embedded JWK.
        if (header.GetPropertyOrNull("typ")?.GetString() != "dpop+jwt") return null;
        if (header.GetPropertyOrNull("alg")?.GetString() != "ES256") return null;
        if (header.GetPropertyOrNull("jwk") is not { } jwk) return null;
        if (jwk.GetPropertyOrNull("kty")?.GetString() != "EC" ||
            jwk.GetPropertyOrNull("crv")?.GetString() != "P-256") return null;
        var x = jwk.GetPropertyOrNull("x")?.GetString();
        var y = jwk.GetPropertyOrNull("y")?.GetString();
        if (x is null || y is null) return null;

        // 2. Signature over ASCII(header.payload) with the embedded public key (JOSE R||S).
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = B64.Decode(x), Y = B64.Decode(y) },
        });
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        if (!ecdsa.VerifyData(signingInput, B64.Decode(parts[2]), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) return null;

        // 3. Claims: htm, htu, iat freshness, optional ath, single-use jti.
        if (!string.Equals(payload.GetPropertyOrNull("htm")?.GetString(), htm, StringComparison.OrdinalIgnoreCase)) return null;
        if (!HtuMatches(payload.GetPropertyOrNull("htu")?.GetString(), htu)) return null;
        if (payload.GetPropertyOrNull("iat")?.GetInt64() is not { } iat) return null;
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - iat) > Window.TotalSeconds) return null;

        if (accessToken is not null)
        {
            var ath = B64.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            if (payload.GetPropertyOrNull("ath")?.GetString() != ath) return null;
        }

        var jti = payload.GetPropertyOrNull("jti")?.GetString();
        if (string.IsNullOrEmpty(jti)) return null;
        // SET key value NX EX window — false if it already existed (replay).
        if (!await _redis.StringSetAsync($"dpop:jti:{jti}", "1", Window, When.NotExists)) return null;

        // 4. jkt = base64url(SHA256(canonical JWK)) — RFC 7638 (members lexicographic).
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return B64.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static bool HtuMatches(string? proofHtu, string expected)
    {
        if (proofHtu is null) return false;
        // Compare without query/fragment (RFC 9449 §4.3).
        static string Norm(string u) => Uri.TryCreate(u, UriKind.Absolute, out var p)
            ? $"{p.Scheme}://{p.Authority}{p.AbsolutePath}".TrimEnd('/') : u.TrimEnd('/');
        return string.Equals(Norm(proofHtu), Norm(expected), StringComparison.OrdinalIgnoreCase);
    }
}

internal static class JsonExtensions
{
    public static JsonElement? GetPropertyOrNull(this JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : null;
}

internal static class B64
{
    public static string Encode(byte[] b) => OidcProvider.Core.Base64UrlText.Encode(b);
    public static byte[] Decode(string s) => OidcProvider.Core.Base64UrlText.Decode(s);
}
