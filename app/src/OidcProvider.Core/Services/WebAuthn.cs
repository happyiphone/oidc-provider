using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OidcProvider.Core.Entities;
using StackExchange.Redis;

namespace OidcProvider.Core.Services;

// WebAuthn / FIDO2 ASSERTION verification (the "navigator.credentials.get" ceremony used
// for second-factor sign-in). This is the well-defined cryptographic core of WebAuthn:
//   verify( signature, authenticatorData || SHA256(clientDataJSON), credentialPublicKey )
// plus the rpIdHash / user-present / challenge / origin / signCount checks.
//
// REGISTRATION (attestation) is deliberately out of scope here — validating attestation
// statements (packed/tpm/android-key/…) is the genuinely hard part and should use a vetted
// library (e.g. Fido2NetLib) in production. Credentials are seeded for this build.
public interface IWebAuthnService
{
    // Registration (navigator.credentials.create) — the enrollment ceremony.
    Task<WebAuthnRegistrationOptions> NewRegistrationOptionsAsync(string sessionId, Guid userId, string username, CancellationToken ct = default);
    Task<WebAuthnCredential?> VerifyRegistrationAsync(string sessionId, WebAuthnAttestation attestation, CancellationToken ct = default);
    // Assertion (navigator.credentials.get) — the login/2FA ceremony.
    Task<WebAuthnOptions> NewAssertionOptionsAsync(string sessionId, UserMfaMethod credential, CancellationToken ct = default);
    Task<WebAuthnOptions> NewLoginOptionsAsync(string key, CancellationToken ct = default); // passwordless
    Task<bool> VerifyAssertionAsync(string sessionId, UserMfaMethod credential, WebAuthnAssertion assertion, CancellationToken ct = default);
}

public sealed record WebAuthnAssertion(string Id, string AuthenticatorData, string ClientDataJSON, string Signature);
public sealed record WebAuthnAttestation(string Id, string AttestationObject, string ClientDataJSON);
public sealed record WebAuthnOptions(string Challenge, string RpId, string CredentialId);
public sealed record WebAuthnRegistrationOptions(string Challenge, string RpId, string RpName, string UserId, string UserName);
// Result of a verified registration: ready to persist as a UserMfaMethod.
public sealed record WebAuthnCredential(string CredentialId, byte[] PublicKey /* X(32)||Y(32) */, uint SignCount);

public sealed class WebAuthnConfig
{
    public string RpId { get; set; } = "localhost";
    public string Origin { get; set; } = "http://localhost:8081";
}

public sealed class WebAuthnService : IWebAuthnService
{
    private readonly IDatabase _redis;
    private readonly WebAuthnConfig _cfg;
    public WebAuthnService(IConnectionMultiplexer mux, WebAuthnConfig cfg)
        => (_redis, _cfg) = (mux.GetDatabase(), cfg);

    // ---- Registration (attestation) ----
    // Supports fmt="none"/self-attestation: we extract and trust the credential public key
    // (standard for passkeys / 2FA). Validating packed/tpm/android-key attestation against
    // the FIDO MDS is out of scope — use Fido2NetLib for that in production (ADR-0002).
    public async Task<WebAuthnRegistrationOptions> NewRegistrationOptionsAsync(
        string sid, Guid userId, string username, CancellationToken ct = default)
    {
        var challenge = B64Url(RandomNumberGenerator.GetBytes(32));
        await _redis.StringSetAsync(RegKey(sid), challenge, TimeSpan.FromMinutes(5));
        return new WebAuthnRegistrationOptions(
            challenge, _cfg.RpId, "OIDC Provider", B64Url(userId.ToByteArray()), username);
    }

    public async Task<WebAuthnCredential?> VerifyRegistrationAsync(
        string sid, WebAuthnAttestation att, CancellationToken ct = default)
    {
        var expected = await _redis.StringGetAsync(RegKey(sid));
        if (expected.IsNullOrEmpty) return null;
        await _redis.KeyDeleteAsync(RegKey(sid));

        // 1. clientDataJSON: type=webauthn.create, challenge + origin binding.
        var clientData = B64UrlDecode(att.ClientDataJSON);
        using var doc = JsonDocument.Parse(clientData);
        var root = doc.RootElement;
        if (root.GetProperty("type").GetString() != "webauthn.create") return null;
        if (root.GetProperty("challenge").GetString() != expected.ToString()) return null;
        if (root.GetProperty("origin").GetString() != _cfg.Origin) return null;

        // 2. attestationObject (CBOR): { fmt, attStmt, authData }.
        byte[]? authData = null; string? fmt = null;
        var reader = new System.Formats.Cbor.CborReader(B64UrlDecode(att.AttestationObject));
        var n = reader.ReadStartMap();
        for (var i = 0; i < n; i++)
        {
            var key = reader.ReadTextString();
            switch (key)
            {
                case "fmt": fmt = reader.ReadTextString(); break;
                case "authData": authData = reader.ReadByteString(); break;
                default: reader.SkipValue(); break; // attStmt etc.
            }
        }
        reader.ReadEndMap();
        if (authData is null || authData.Length < 55) return null;

        // 3. authData: rpIdHash, flags (AT bit), signCount, attestedCredentialData.
        var rpIdHash = SHA256.HashData(Encoding.ASCII.GetBytes(_cfg.RpId));
        if (!CryptographicOperations.FixedTimeEquals(authData.AsSpan(0, 32), rpIdHash)) return null;
        var flags = authData[32];
        if ((flags & 0x40) == 0) return null;                     // AT (attested credential data) present
        var signCount = (uint)((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]);
        // attestedCredentialData = aaguid(16) + credIdLen(2) + credId + COSEpublicKey
        var credIdLen = (authData[53] << 8) | authData[54];
        if (authData.Length < 55 + credIdLen) return null;
        var credId = authData[55..(55 + credIdLen)];
        var coseKey = authData[(55 + credIdLen)..];

        // 4. COSE EC2 P-256 public key (map: 1=kty,3=alg,-1=crv,-2=x,-3=y).
        byte[]? x = null, y = null; int kty = 0, alg = 0, crv = 0;
        var ck = new System.Formats.Cbor.CborReader(coseKey);
        var m = ck.ReadStartMap();
        for (var i = 0; i < m; i++)
        {
            var label = ck.ReadInt32();
            switch (label)
            {
                case 1: kty = ck.ReadInt32(); break;
                case 3: alg = ck.ReadInt32(); break;
                case -1: crv = ck.ReadInt32(); break;
                case -2: x = ck.ReadByteString(); break;
                case -3: y = ck.ReadByteString(); break;
                default: ck.SkipValue(); break;
            }
        }
        if (kty != 2 || alg != -7 || crv != 1 || x is null || y is null) return null; // EC2/ES256/P-256
        var pub = new byte[64];
        Buffer.BlockCopy(x, 0, pub, 0, 32);
        Buffer.BlockCopy(y, 0, pub, 32, 32);
        return new WebAuthnCredential(B64Url(credId), pub, signCount);
    }

    public async Task<WebAuthnOptions> NewAssertionOptionsAsync(string sid, UserMfaMethod cred, CancellationToken ct = default)
    {
        var challenge = B64Url(RandomNumberGenerator.GetBytes(32));
        await _redis.StringSetAsync(Key(sid), challenge, TimeSpan.FromMinutes(5)); // bound to session
        return new WebAuthnOptions(challenge, _cfg.RpId, cred.SecretRef);
    }

    // Usernameless / passwordless login: a challenge bound to a pre-session key (cookie), with no
    // allowCredentials so the browser offers any discoverable passkey for this RP.
    public async Task<WebAuthnOptions> NewLoginOptionsAsync(string key, CancellationToken ct = default)
    {
        var challenge = B64Url(RandomNumberGenerator.GetBytes(32));
        await _redis.StringSetAsync(Key(key), challenge, TimeSpan.FromMinutes(5));
        return new WebAuthnOptions(challenge, _cfg.RpId, ""); // empty credentialId → discoverable
    }

    public async Task<bool> VerifyAssertionAsync(string sid, UserMfaMethod cred, WebAuthnAssertion a, CancellationToken ct = default)
    {
        var expected = await _redis.StringGetAsync(Key(sid));
        if (expected.IsNullOrEmpty) return false;
        await _redis.KeyDeleteAsync(Key(sid));                         // single-use challenge

        if (!string.Equals(a.Id, cred.SecretRef, StringComparison.Ordinal)) return false;

        // 1. clientDataJSON: type, challenge binding, origin.
        var clientDataBytes = B64UrlDecode(a.ClientDataJSON);
        using var doc = JsonDocument.Parse(clientDataBytes);
        var root = doc.RootElement;
        if (root.GetProperty("type").GetString() != "webauthn.get") return false;
        if (root.GetProperty("challenge").GetString() != expected.ToString()) return false; // replay/CSRF
        if (root.GetProperty("origin").GetString() != _cfg.Origin) return false;

        // 2. authenticatorData: rpIdHash, user-present flag, signCount.
        var authData = B64UrlDecode(a.AuthenticatorData);
        if (authData.Length < 37) return false;
        var rpIdHash = SHA256.HashData(Encoding.ASCII.GetBytes(_cfg.RpId));
        if (!CryptographicOperations.FixedTimeEquals(authData.AsSpan(0, 32), rpIdHash)) return false;
        var flags = authData[32];
        if ((flags & 0x01) == 0) return false;                          // UP (user present) must be set
        var signCount = (uint)((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]);

        // 3. signature over authenticatorData || SHA256(clientDataJSON).
        var signedData = new byte[authData.Length + 32];
        Buffer.BlockCopy(authData, 0, signedData, 0, authData.Length);
        Buffer.BlockCopy(SHA256.HashData(clientDataBytes), 0, signedData, authData.Length, 32);

        using var ecdsa = ImportPublicKey(cred.PublicKey!);
        var ok = ecdsa.VerifyData(signedData, B64UrlDecode(a.Signature),
            HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence); // WebAuthn ES256 sig = DER
        if (!ok) return false;

        // 4. clone detection: signCount must advance (unless authenticator reports 0).
        if (signCount != 0 && signCount <= cred.SignCount) return false;
        cred.SignCount = signCount;
        cred.LastUsedAt = DateTimeOffset.UtcNow;
        return true;
    }

    private static ECDsa ImportPublicKey(byte[] xy) // stored as X(32)||Y(32)
    {
        var p = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = xy[..32], Y = xy[32..64] },
        };
        return ECDsa.Create(p);
    }

    private static string Key(string sid) => $"wa:chal:{sid}";
    private static string RegKey(string sid) => $"wa:reg:{sid}";
    private static string B64Url(byte[] b) => Base64UrlText.Encode(b);
    private static byte[] B64UrlDecode(string s) => Base64UrlText.Decode(s);
}
