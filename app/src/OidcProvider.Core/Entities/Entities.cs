using System.ComponentModel.DataAnnotations;

namespace OidcProvider.Core.Entities;

// NOTE on storage split: OpenIddict's EF integration owns the protocol entities
// (applications/clients, authorizations, tokens, scopes) — that is where auth codes
// and refresh tokens physically live, and where rolling-refresh + reuse rejection are
// enforced. The entities below are the SUPPLEMENTARY durable state our policy owns:
// users, MFA, pairwise subjects, consent, signing-key lifecycle, audit, and per-client
// policy flags. This mirrors docs/oidc-provider/schema.sql (which models the same
// concepts; OpenIddict generates its own tables for the protocol half).

public sealed class AppUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [MaxLength(256)] public string? Username { get; set; }
    [MaxLength(320)] public string? Email { get; set; }
    public bool EmailVerified { get; set; }
    public string? PasswordHash { get; set; }            // argon2id/PBKDF2; null if federated-only
    // Bump on any credential change → revoke all sessions/tokens issued earlier (threat tree (c)).
    public DateTimeOffset CredentialsChangedAt { get; set; } = DateTimeOffset.UtcNow;
    public string ProfileClaimsJson { get; set; } = "{}";
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public List<UserMfaMethod> MfaMethods { get; set; } = new();
}

public enum MfaKind { Totp, WebAuthn, RecoveryCode }

public sealed class UserMfaMethod
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public AppUser? User { get; set; }
    public MfaKind Kind { get; set; }
    public string SecretRef { get; set; } = "";          // KMS-encrypted secret / WebAuthn credential id
    public byte[]? PublicKey { get; set; }               // WebAuthn COSE key
    public long SignCount { get; set; }                  // WebAuthn clone detection
    public string? Label { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastUsedAt { get; set; }
}

// ADR-0010: pairwise PPID per client/sector. Persisted so the derivation key can rotate
// and to power an admin PPID->user resolver.
public sealed class SubjectIdentifier
{
    public Guid UserId { get; set; }
    public string SectorIdentifier { get; set; } = "";
    public string Ppid { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class Consent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string ClientId { get; set; } = "";
    public List<string> ScopesGranted { get; set; } = new();
    public DateTimeOffset GrantedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

// ADR-0009/0010: per-client policy not captured by OpenIddict's application entity.
public sealed class ClientPolicy
{
    public string ClientId { get; set; } = "";
    public string? SectorIdentifier { get; set; }
    public bool RequirePar { get; set; } = true;
    public bool DpopBound { get; set; }
    public string SubjectType { get; set; } = "pairwise"; // or "public"
}

public enum KeyStatus { Next, Active, Retired }

// ADR-0005: only public material + KMS handle live here; private key never does.
public sealed class SigningKeyRecord
{
    [MaxLength(128)] public string Kid { get; set; } = "";
    public string Alg { get; set; } = "ES256";
    public string KmsKeyRef { get; set; } = "";          // handle to KMS/HSM private key (or "dev")
    public byte[] PublicKeyDer { get; set; } = Array.Empty<byte>(); // SubjectPublicKeyInfo
    public KeyStatus Status { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? NotAfter { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

// threat T16: append-only audit. App has INSERT only; optional hash-chain.
public sealed class AuditEntry
{
    public long Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; } = DateTimeOffset.UtcNow;
    public Guid? ActorUser { get; set; }
    public string? ClientId { get; set; }
    public string EventType { get; set; } = "";
    public string DetailJson { get; set; } = "{}";
    public byte[]? PrevHash { get; set; }
    public byte[]? RowHash { get; set; }
}
