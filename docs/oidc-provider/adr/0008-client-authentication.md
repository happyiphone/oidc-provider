# 8. Client authentication: prefer `private_key_jwt` over shared secrets

**Status:** Accepted

## Context

Confidential clients authenticate to the token endpoint. The classic methods —
`client_secret_basic` / `client_secret_post` — transmit a shared secret on every call.
Shared secrets leak through logs, config sprawl, and breaches, and rotating them is
disruptive. Asymmetric client authentication (`private_key_jwt`, RFC 7523) instead has
the client sign a short-lived JWT assertion with its private key; the provider verifies
with the client's registered public key. The secret never traverses the wire.

## Decision

For confidential clients we **prefer and recommend `private_key_jwt`** (and accept
`tls_client_auth` / mutual-TLS where infrastructure supports it). `client_secret_*` is
permitted only for low-risk legacy clients and never for high-assurance ones. Public
clients use **none** + PKCE (see [0001](./0001-protocol-baseline.md)). Client public keys
/ `jwks_uri` are captured at registration ([endpoint spec](../endpoint-spec.md)).

## Consequences

**Positive:** No shared secret in transit or at rest on the provider for asymmetric
clients; key rotation is client-side and non-disruptive; assertions are short-lived and
audience-bound, resisting replay. Aligns with FAPI requirements for later phases.

**Negative:** Clients must manage a keypair and JWKS endpoint — more setup than a secret.
The provider must validate assertion `aud`, `exp`, `jti` (replay cache) and the signing
alg strictly.

## Alternatives considered

- **`client_secret_basic` as default:** simplest for client devs, but perpetuates shared
  secrets — relegated to legacy-only.
- **mTLS only:** strong and sender-constrains tokens too, but demands client-cert
  infrastructure many clients lack — offered, not mandated.
