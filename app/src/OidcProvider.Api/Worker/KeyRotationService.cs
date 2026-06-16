using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Microsoft.Extensions.Options;
using OidcProvider.Api.Signing;
using OidcProvider.Core.Entities;
using OidcProvider.Core.Signing;

namespace OidcProvider.Api.Worker;

// ADR-0005 — the 3-state rotation job (next → active → retired), KMS mode only.
// Mirrors docs/oidc-provider/kms-signing.md §3. Runs on an interval and is also safe
// to invoke on demand for emergency rotation.
public sealed class KeyRotationService : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly IAmazonKeyManagementService _kms;
    private readonly OidcSigningConfig _cfg;
    private readonly ILogger<KeyRotationService> _log;
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);
    private static readonly TimeSpan MaxAccessTokenLifetime = TimeSpan.FromHours(1);

    public KeyRotationService(IServiceScopeFactory scopes, IAmazonKeyManagementService kms,
        IOptions<OidcSigningConfig> cfg, ILogger<KeyRotationService> log)
        => (_scopes, _kms, _cfg, _log) = (scopes, kms, cfg.Value, log);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RotateAsync(stoppingToken); }
            catch (Exception ex) { _log.LogError(ex, "Key rotation failed"); }
            await Task.Delay(Interval, stoppingToken);
        }
    }

    public async Task RotateAsync(CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<ISigningKeyStore>();

        // 1. Ensure a `next` exists, published ahead of activation.
        var next = await store.GetByStatusAsync(KeyStatus.Next, ct);
        if (next is null)
        {
            var created = await _kms.CreateKeyAsync(new CreateKeyRequest
            { KeySpec = KeySpec.ECC_NIST_P256, KeyUsage = KeyUsageType.SIGN_VERIFY }, ct);
            var keyId = created.KeyMetadata.KeyId;
            var pub = await _kms.GetPublicKeyAsync(new GetPublicKeyRequest { KeyId = keyId }, ct);
            await store.InsertAsync(new SigningKeyRecord
            {
                Kid = "k-" + Guid.NewGuid().ToString("n")[..12],
                Alg = "ES256",
                KmsKeyRef = keyId,
                PublicKeyDer = pub.PublicKey.ToArray(),
                Status = KeyStatus.Next,
                NotBefore = DateTimeOffset.UtcNow.AddMinutes(_cfg.Kms.KeyPropagationMinutes),
            }, ct);
            _log.LogInformation("Published next signing key; will activate after propagation.");
            return; // activate on a later run, after verifiers have cached it (AC-T10-2)
        }

        // 2. Promote once the propagation window has elapsed.
        if (next.NotBefore is { } nb && nb > DateTimeOffset.UtcNow) return;
        await store.PromoteAsync(next.Kid, ct);   // active→retired, next→active (AC-T7-2)
        _log.LogInformation("Activated signing key {Kid}.", next.Kid);

        // 3. Drop retired keys whose tokens have all expired.
        await store.PurgeExpiredRetiredAsync(MaxAccessTokenLifetime, ct);
    }
}
