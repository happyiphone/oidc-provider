using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OidcProvider.Core.Data;
using OidcProvider.Core.Entities;

namespace OidcProvider.Core.Signing;

// ----------------------------------------------------------------------------
// ADR-0005 — signing-key lifecycle store (next → active → retired).
// ----------------------------------------------------------------------------
public interface ISigningKeyStore
{
    Task<IReadOnlyList<SigningKeyRecord>> GetPublishableAsync(CancellationToken ct = default);
    Task<SigningKeyRecord?> GetByStatusAsync(KeyStatus status, CancellationToken ct = default);
    Task InsertAsync(SigningKeyRecord key, CancellationToken ct = default);
    Task PromoteAsync(string activateKid, CancellationToken ct = default);
    Task PurgeExpiredRetiredAsync(TimeSpan olderThan, CancellationToken ct = default);
}

public sealed class EfSigningKeyStore : ISigningKeyStore
{
    private readonly AuthDbContext _db;
    public EfSigningKeyStore(AuthDbContext db) => _db = db;

    // Publish active + next + retired-but-not-yet-expired (verifiers prefetch `next`).
    public async Task<IReadOnlyList<SigningKeyRecord>> GetPublishableAsync(CancellationToken ct = default)
        => await _db.SigningKeys
            .Where(k => k.Status != KeyStatus.Retired
                     || k.NotAfter == null || k.NotAfter > DateTimeOffset.UtcNow)
            .ToListAsync(ct);

    public Task<SigningKeyRecord?> GetByStatusAsync(KeyStatus status, CancellationToken ct = default)
        => _db.SigningKeys.FirstOrDefaultAsync(k => k.Status == status, ct);

    public async Task InsertAsync(SigningKeyRecord key, CancellationToken ct = default)
    { _db.SigningKeys.Add(key); await _db.SaveChangesAsync(ct); }

    // active → retired, next → active, in one transaction. The partial unique index
    // uq(active) guarantees we never end with two active keys under a race.
    public async Task PromoteAsync(string activateKid, CancellationToken ct = default)
    {
        await using var tx = await _db.Database.BeginTransactionAsync(ct);
        var current = await _db.SigningKeys.FirstOrDefaultAsync(k => k.Status == KeyStatus.Active, ct);
        if (current is not null)
        {
            current.Status = KeyStatus.Retired;
            current.NotAfter = DateTimeOffset.UtcNow.AddDays(1); // keep in JWKS past token TTL
        }
        var next = await _db.SigningKeys.FirstAsync(k => k.Kid == activateKid, ct);
        next.Status = KeyStatus.Active;
        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task PurgeExpiredRetiredAsync(TimeSpan olderThan, CancellationToken ct = default)
    {
        var cutoff = DateTimeOffset.UtcNow - olderThan;
        var dead = await _db.SigningKeys
            .Where(k => k.Status == KeyStatus.Retired && k.NotAfter != null && k.NotAfter < cutoff)
            .ToListAsync(ct);
        _db.SigningKeys.RemoveRange(dead);
        await _db.SaveChangesAsync(ct);
        // NB: schedule KMS key deletion separately, well after JWKS removal.
    }
}

// ----------------------------------------------------------------------------
// ADR-0005 — KMS-backed ECDSA key. Private Sign is a remote call; Verify is local.
// (Mirrors docs/oidc-provider/kms-signing.md §1.)
// ----------------------------------------------------------------------------
public sealed class KmsEcdsaSecurityKey : ECDsaSecurityKey
{
    public string KmsKeyId { get; }
    public KmsEcdsaSecurityKey(ECDsa publicOnly, string kid, string kmsKeyId) : base(publicOnly)
    { KeyId = kid; KmsKeyId = kmsKeyId; }
}

public sealed class KmsCryptoProvider : ICryptoProvider
{
    private readonly IAmazonKeyManagementService _kms;
    public KmsCryptoProvider(IAmazonKeyManagementService kms) => _kms = kms;

    public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        => algorithm == SecurityAlgorithms.EcdsaSha256 && args.FirstOrDefault() is KmsEcdsaSecurityKey;

    public object Create(string algorithm, params object[] args)
        => new KmsSignatureProvider((KmsEcdsaSecurityKey)args[0], algorithm, _kms);

    public void Release(object cryptoInstance) => (cryptoInstance as IDisposable)?.Dispose();
}

public sealed class KmsSignatureProvider : SignatureProvider
{
    private readonly KmsEcdsaSecurityKey _key;
    private readonly IAmazonKeyManagementService _kms;
    public KmsSignatureProvider(KmsEcdsaSecurityKey key, string alg, IAmazonKeyManagementService kms)
        : base(key, alg) { _key = key; _kms = kms; }

    public override byte[] Sign(byte[] input)
    {
        var digest = SHA256.HashData(input);
        var resp = _kms.SignAsync(new SignRequest
        {
            KeyId = _key.KmsKeyId,
            Message = new MemoryStream(digest),
            MessageType = MessageType.DIGEST,
            SigningAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256
        }).GetAwaiter().GetResult();
        return DerToConcat(resp.Signature.ToArray(), 32); // DER → JOSE R||S
    }

    public override bool Verify(byte[] input, byte[] signature)
        => _key.ECDsa.VerifyData(input, signature, HashAlgorithmName.SHA256,
               DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    protected override void Dispose(bool disposing) { }

    private static byte[] DerToConcat(byte[] der, int n)
    {
        var seq = new System.Formats.Asn1.AsnReader(der,
            System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
        var r = seq.ReadInteger(); var s = seq.ReadInteger();
        var outp = new byte[n * 2];
        Write(r, outp.AsSpan(0, n)); Write(s, outp.AsSpan(n, n));
        return outp;
        static void Write(System.Numerics.BigInteger v, Span<byte> dst)
        { var b = v.ToByteArray(true, true); b.AsSpan().CopyTo(dst[(dst.Length - b.Length)..]); }
    }
}

// ----------------------------------------------------------------------------
// ADR-0007 — refresh-token family facade. OpenIddict natively rejects a reused
// (already-redeemed) refresh token; on that signal we revoke the whole family,
// and we expose subject-wide revocation for credential changes (tree (c)).
// ----------------------------------------------------------------------------
public interface IOpenIddictTokenManagerFacade
{
    Task RevokeFamilyAsync(string authorizationId, CancellationToken ct = default);
    Task RevokeAllForSubjectAsync(string subject, CancellationToken ct = default);
}
