# 11. PKCE mandatory for all clients; S256 only, `plain` rejected

**Status:** Accepted

## Context

PKCE (RFC 7636) was introduced to protect *public* clients from authorization-code
interception, but the OAuth 2.0 Security BCP (RFC 9700) and OAuth 2.1 extend the
requirement to **all** clients, including confidential ones — a confidential client's
network path or browser leg can still leak a code, and a single policy ("PKCE always")
removes any per-client downgrade decision. PKCE defines two transforms: `plain` (the
challenge *is* the verifier) and `S256` (the challenge is `BASE64URL(SHA256(verifier))`).
`plain` offers no protection against an attacker who can read the authorization request,
so it must not be accepted. [ADR-0001](./0001-protocol-baseline.md) adopts OAuth 2.1
broadly; this ADR records the PKCE specifics as a first-class, testable decision because
the implementation and test suites reference it directly.

## Decision

PKCE is **mandatory on every authorization request**, public and confidential alike. The
provider accepts **only `code_challenge_method=S256`**; requests with
`code_challenge_method=plain`, or with no `code_challenge` at all, are rejected with
`invalid_request` at `/authorize` (before any UI). At `/token`, redemption requires a
`code_verifier` whose `S256` transform equals the stored challenge, else `invalid_grant`.

## Consequences

**Positive:** Eliminates code-interception value uniformly (threat T1) and forecloses the
PKCE-downgrade attack (threat T11) by construction — there is no `plain` path to downgrade
*to*. One rule, no per-client exceptions to audit.

**Negative:** Any client SDK too old to support PKCE S256 is unsupported by policy (an
accepted, deliberate cost). Confidential clients that previously relied solely on a client
secret now also carry a verifier — negligible client-side effort.

## Alternatives considered

- **PKCE only for public clients:** the common pre-2.1 stance; rejected — leaves a
  per-client policy surface and a code-leak window for confidential clients.
- **Accept `plain` for "simple" clients:** rejected — `plain` provides no interception
  protection and reintroduces the downgrade attack.

## Enforcement & verification

- OpenIddict: `RequireProofKeyForCodeExchange()`
  ([`openiddict-implementation.md`](../openiddict-implementation.md) §1).
- Tests: `AC-T11-1..3` and `AC-T1-4` ([`abuse-case-tests.md`](../abuse-case-tests.md)).
