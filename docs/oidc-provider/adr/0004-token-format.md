# 4. Token format: JWT (ES256) access tokens + opaque refresh tokens

**Status:** Accepted

## Context

Access tokens may be self-contained (JWT, RFC 9068) or opaque (a random handle
validated by introspection). JWTs let resource servers validate locally against
published JWKS — no per-request call to the provider — at the cost of being unrevocable
until expiry. Refresh tokens, by contrast, are long-lived secrets presented only to the
token endpoint, so they gain nothing from being self-contained and lose much (a leaked
readable long-lived JWT is worse than an opaque handle).

## Decision

**Access tokens are JWTs signed with ES256** (ECDSA P-256). **Refresh tokens are opaque,
high-entropy, server-stored handles.** Access-token TTL is short (5–15 min) so the
non-revocability window is small; introspection (RFC 7662) remains available for
resource servers that need authoritative revocation checks.

## Consequences

**Positive:** Resource servers validate access tokens statelessly via JWKS. ES256
signatures and keys are far smaller and faster to verify than RS256, shrinking tokens
and JWKS. Opaque refresh tokens are trivially revocable and carry no readable payload.

**Negative:** JWT access tokens can't be revoked mid-life — mitigated by short TTL +
[refresh rotation](./0007-refresh-token-rotation.md) + optional introspection. ES256
requires correct curve/alg pinning to avoid confusion attacks (see threat model).

## Alternatives considered

- **RS256 access tokens:** widely supported but larger keys/signatures; acceptable
  fallback if a consumer ecosystem mandates RSA. We publish both only if forced to.
- **Opaque access tokens + mandatory introspection:** strongest revocation, but every
  resource-server request hits the provider — rejected as the default for scalability.
