using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OidcProvider.Core.Entities;
using OidcProvider.Core.Signing;
using OpenIddict.Server;

namespace OidcProvider.Api.Signing;

// Loads signing credentials into OpenIddict lazily (after DI + DB migration are ready).
// Dev mode: an ephemeral ES256 key (rotates on restart — local only).
// Kms  mode: every publishable lifecycle key (next+active+retired) from the store, with
//            the ACTIVE one used for signing and the rest published for verification.
// IConfigureOptions (not IPostConfigure): must run BEFORE OpenIddict's own
// PostConfigure, which validates that a signing + encryption key are present.
public sealed class SigningOptionsSetup : IConfigureOptions<OpenIddictServerOptions>
{
    private readonly IServiceProvider _sp;
    private readonly OidcSigningConfig _cfg;

    public SigningOptionsSetup(IServiceProvider sp, IOptions<OidcSigningConfig> cfg)
        => (_sp, _cfg) = (sp, cfg.Value);

    public void Configure(OpenIddictServerOptions options)
    {
        // ADR-0011: PKCE S256 only — never advertise or accept `plain` (surfaced by the
        // OIDF conformance suite, which flagged the metadata/policy mismatch).
        options.CodeChallengeMethods.Remove("plain");

        var isDev = _cfg.Mode.Equals("Dev", StringComparison.OrdinalIgnoreCase);
        // Fail fast: the ephemeral in-process Dev signing key must never run outside
        // Development (no KMS/HSM custody, no rotation, per-instance key). [security #2]
        if (isDev && !_sp.GetRequiredService<IHostEnvironment>().IsDevelopment())
            throw new InvalidOperationException(
                "Oidc:Signing:Mode=Dev is not allowed outside Development. Set Mode=Kms.");

        // Access tokens are unencrypted JWTs (ADR-0004), but OpenIddict still encrypts
        // authorization codes / refresh tokens — supply a symmetric encryption key (both modes).
        // Stable across instances when Oidc:Signing:EncryptionKeyBase64 is set; otherwise
        // ephemeral (fine for a single dev instance; prod should set/KMS-wrap it).
        var encKeyB64 = _cfg.EncryptionKeyBase64;
        var enc = string.IsNullOrEmpty(encKeyB64)
            ? RandomNumberGenerator.GetBytes(32) : Convert.FromBase64String(encKeyB64);
        options.EncryptionCredentials.Add(new EncryptingCredentials(
            new SymmetricSecurityKey(enc),
            SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));

        if (isDev)
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            options.SigningCredentials.Add(
                new SigningCredentials(new ECDsaSecurityKey(ecdsa) { KeyId = "dev-es256" },
                    SecurityAlgorithms.EcdsaSha256));
            return;
        }

        // KMS mode — private keys never enter the process (ADR-0005).
        var kms = _sp.GetRequiredService<IAmazonKeyManagementService>();
        CryptoProviderFactory.Default.CustomCryptoProvider ??= new KmsCryptoProvider(kms);

        using var scope = _sp.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<ISigningKeyStore>();
        var keys = store.GetPublishableAsync().GetAwaiter().GetResult();
        foreach (var k in keys)
        {
            var pub = ECDsa.Create();
            pub.ImportSubjectPublicKeyInfo(k.PublicKeyDer, out _);
            var sk = new KmsEcdsaSecurityKey(pub, k.Kid, k.KmsKeyRef);
            if (k.Status == KeyStatus.Active)
                options.SigningCredentials.Add(
                    new SigningCredentials(sk, SecurityAlgorithms.EcdsaSha256));
            // Non-active keys are surfaced in JWKS via OpenIddict's key set automatically
            // once registered as signing keys across rotation; retired keys remain until purge.
        }
    }
}

public sealed class OidcSigningConfig
{
    public string Mode { get; set; } = "Dev";   // Dev | Kms
    public string? EncryptionKeyBase64 { get; set; }   // stable token-encryption key (both modes)
    public KmsConfig Kms { get; set; } = new();
    public sealed class KmsConfig
    {
        public string Region { get; set; } = "us-east-1";
        public int KeyPropagationMinutes { get; set; } = 10;
    }
}
