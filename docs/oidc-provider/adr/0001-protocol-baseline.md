# 1. Protocol baseline: OAuth 2.1 + OpenID Connect Core 1.0

**Status:** Accepted

## Context

OAuth 2.0 (RFC 6749) accreted multiple grant types over a decade, several of which
are now recognised as inherently unsafe: the **implicit** grant leaks tokens through
redirect URIs and browser history, and the **Resource Owner Password Credentials
(ROPC)** grant requires the client to handle user passwords directly, defeating the
point of delegated authorization. OAuth 2.1 is the consolidation draft that folds in
a decade of security BCP: PKCE becomes mandatory, implicit and ROPC are removed,
bearer tokens in query strings are forbidden, and exact redirect-URI matching is
required. OpenID Connect Core 1.0 layers authentication (the ID token) on top.

## Decision

We target **OAuth 2.1** as the authorization framework and **OpenID Connect Core 1.0
+ Discovery 1.0** as the identity layer. We implement only the Authorization Code
grant (with PKCE), Refresh Token grant, Client Credentials grant, and Device
Authorization grant. We do **not** implement implicit or ROPC.

## Consequences

**Positive:** Whole classes of vulnerabilities (token leakage via fragment, password
handling by clients) are removed by construction rather than by configuration. PKCE
mandatory-everywhere means no public-client downgrade path. Aligns with RFC 9700 BCP.

**Negative:** Legacy clients built around implicit flow must migrate to code+PKCE
(now trivial for SPAs with modern libraries). Some very old SDKs may not support PKCE
and are unsupported by policy.

## Alternatives considered

- **Plain OAuth 2.0 (RFC 6749) for "compatibility":** rejected — re-admits the unsafe
  grants and shifts security burden to configuration we'd have to police forever.
- **Proprietary/custom token protocol:** rejected — no interop, no conformance suite,
  no third-party security review. See [0002](./0002-build-vs-buy-core.md).
