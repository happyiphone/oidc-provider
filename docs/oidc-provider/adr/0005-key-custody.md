# 5. Key custody: private signing keys live in KMS/HSM only

**Status:** Accepted

## Context

Compromise of a token-signing private key is catastrophic and total: an attacker can
mint valid ID and access tokens for any user, and detection is hard. Keys held in
application memory, environment variables, or config files are exposed to memory
disclosure, log leakage, container image scraping, and broad blast radius on host
compromise.

## Decision

**Private signing keys are generated in and never leave a KMS/HSM** (cloud KMS or a
hardware HSM). The application calls the KMS to *sign*; it never holds private key
material. The app holds only **public** keys, which it publishes at `/jwks.json`. Keys
follow a three-state lifecycle — `next` (published in JWKS before first use), `active`
(currently signing), `retired` (still in JWKS for verification until tokens expire) —
enabling zero-downtime rotation. See [0004](./0004-token-format.md).

## Consequences

**Positive:** A full application/host compromise does not yield signing capability
beyond the attacker's access window to the KMS (which is itself access-controlled and
audited). Rotation is routine and non-disruptive because verifiers prefetch the `next`
key. KMS provides an audit trail of every signing operation.

**Negative:** Every token issuance incurs a KMS round trip — mitigated by caching
short-lived signing where the KMS supports it, batching, and the short critical path.
Operational dependency on KMS availability (mitigate with multi-region KMS / HA HSM).

## Alternatives considered

- **In-memory keys loaded from a secrets manager at boot:** simpler, faster signing, but
  keys are recoverable from a compromised process — rejected for a security product.
- **Static long-lived key in config:** rejected outright; no rotation, maximal blast
  radius.
