# 7. Refresh tokens: rotation with token-family reuse detection

**Status:** Accepted

## Context

Refresh tokens are long-lived and, for public clients, cannot be protected by a client
secret. A stolen refresh token would otherwise grant indefinite access. The OAuth 2.0
Security BCP (RFC 9700) requires that refresh tokens for public clients be either
sender-constrained or rotated, and recommends reuse detection.

## Decision

Every refresh-token redemption **rotates** the token: the old token is invalidated and a
new one issued within the same logical **token family** (a chain rooted at the original
grant). If a **already-used (rotated-out) refresh token is presented again**, we treat it
as a breach signal and **revoke the entire family**, forcing re-authentication. Families
are tracked in PostgreSQL (see [0006](./0006-storage-split.md)).

## Consequences

**Positive:** A stolen refresh token is useful at most once; the legitimate client's next
rotation (or the thief's reuse) trips family revocation, evicting the attacker. Bounds
the value of token exfiltration without requiring DPoP everywhere (though DPoP composes —
see [0009](./0009-sender-constraining.md)).

**Negative:** Network races (client retries after a dropped response) can present a token
that *looks* reused; we mitigate with a short grace window / idempotent rotation keyed on
the request so legitimate retries don't nuke the family. Requires durable family state and
careful concurrency control on redemption.

## Alternatives considered

- **Non-rotating long-lived refresh tokens:** simplest, but a single leak = permanent
  access — rejected, violates RFC 9700.
- **Rotation without reuse detection:** better, but silently tolerates a thief who races
  the legitimate client — rejected; reuse detection is the point.
