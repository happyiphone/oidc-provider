# C4 Component — Token Endpoint

`POST /token` is the most security-critical surface in the provider: it converts proofs
of prior authorization (an authorization code, a refresh token, a client assertion) into
issued tokens. Every grant type funnels through one authentication + validation pipeline
before any token is minted. This document decomposes the container into components.

## Component diagram

```mermaid
C4Component
title Token Endpoint — Components

Container_Boundary(te, "Token Endpoint") {
  Component(auth, "Request Authenticator", "Authenticates the client: private_key_jwt (RFC 7523), client_secret_*, or none+PKCE for public clients")
  Component(dpop, "DPoP Proof Validator", "Validates RFC 9449 DPoP proof; binds issued tokens to client key (jkt)")
  Component(router, "Grant Router", "Dispatches by grant_type to a handler")
  Component(gc, "Code Grant Handler", "authorization_code")
  Component(gr, "Refresh Grant Handler", "refresh_token")
  Component(gcc, "Client-Credentials Handler", "client_credentials")
  Component(gd, "Device Grant Handler", "urn:...:device_code")
  Component(pkce, "PKCE Verifier", "S256(code_verifier) == stored code_challenge")
  Component(code, "Code Consumer", "Atomic single-use read of auth code from Redis (GETDEL)")
  Component(rot, "Refresh Rotator", "Rotates RT; detects family reuse → revoke family")
  Component(claims, "Claims Assembler", "Resolves scopes→claims, pairwise sub, acr/amr, at_hash")
  Component(signer, "Token Signer", "Builds JWT; signs via KMS (ES256)")
  Component(resp, "Response Builder", "RFC 6749 token response / RFC 6749 error JSON")
}

ContainerDb(redis, "Redis", "Auth codes, PAR, sessions (TTL)")
ContainerDb(pg, "PostgreSQL", "Grants, clients, refresh-token families")
System_Ext(kms, "KMS / HSM", "Private signing keys")

Rel(auth, dpop, "then")
Rel(dpop, router, "authenticated request")
Rel(router, gc, "authorization_code")
Rel(router, gr, "refresh_token")
Rel(router, gcc, "client_credentials")
Rel(router, gd, "device_code")
Rel(gc, code, "consume code")
Rel(code, redis, "GETDEL")
Rel(gc, pkce, "verify")
Rel(gr, rot, "rotate")
Rel(rot, pg, "family state")
Rel(gc, claims, "build")
Rel(gr, claims, "build")
Rel(gcc, claims, "build")
Rel(gd, claims, "build")
Rel(claims, pg, "read grant/user")
Rel(claims, signer, "sign")
Rel(signer, kms, "sign ES256")
Rel(signer, resp, "tokens")
Rel(dpop, resp, "bind jkt")
```

## Component responsibilities

| Component | Responsibility | Key validations | Failure → error |
|---|---|---|---|
| Request Authenticator | Authenticate the client | `private_key_jwt`: verify sig, `aud`=token endpoint, `exp`, `jti` not replayed; secret: constant-time compare | `invalid_client` (401) |
| DPoP Proof Validator | Validate DPoP proof, derive `jkt` | `htm`/`htu` match, `iat` fresh, `jti` unreplayed, key matches bound token | `invalid_dpop_proof` / `invalid_token` (400/401) |
| Grant Router | Dispatch by `grant_type` | grant_type registered for this client | `unsupported_grant_type` / `unauthorized_client` (400) |
| Code Grant Handler | Exchange auth code | code exists, not expired, bound to this client + `redirect_uri` | `invalid_grant` (400) |
| Code Consumer | Single-use code read | atomic `GETDEL`; absent ⇒ replay/expired | `invalid_grant` (400) |
| PKCE Verifier | Enforce PKCE | `S256(code_verifier) == code_challenge`; method must be S256 | `invalid_grant` (400) |
| Refresh Grant Handler | Exchange refresh token | token active, not rotated-out | `invalid_grant` (400) |
| Refresh Rotator | Rotate + reuse-detect | rotated-out token presented ⇒ **revoke family** | `invalid_grant` (400) + family revoke |
| Client-Credentials Handler | Machine-to-machine | client allowed, requested scope ⊆ client scope | `invalid_scope` (400) |
| Device Grant Handler | Poll device code | code approved? else `authorization_pending`/`slow_down` | `authorization_pending` (400) |
| Claims Assembler | scopes→claims, pairwise `sub`, `at_hash`, `acr`/`amr` | scope grant present; audience correct | `invalid_scope` (400) |
| Token Signer | Build + sign JWT via KMS | correct `kid`, alg pinned ES256, `iss`/`aud`/`exp` set | 500 (fail closed) |
| Response Builder | Emit token or error JSON | no token in error path; `Cache-Control: no-store` | — |

## Pipeline narrative — `grant_type=authorization_code`

1. **Request Authenticator** authenticates the client (asymmetric assertion preferred per
   [ADR-0008](./adr/0008-client-authentication.md)). Public clients carry no secret —
   PKCE is the proof. Failure ⇒ `invalid_client`.
2. **DPoP Proof Validator** (if a `DPoP` header is present, or required for this client)
   validates the proof and derives the confirmation key `jkt` to bind into the tokens.
3. **Grant Router** confirms `authorization_code` is permitted for the client and
   dispatches to the **Code Grant Handler**.
4. **Code Consumer** does an **atomic single-use** fetch of the code from Redis
   (`GETDEL`). A miss means already-used or expired ⇒ `invalid_grant`. *(non-negotiable)*
5. The handler checks the **`redirect_uri` is byte-for-byte the one bound to the code**
   ⇒ else `invalid_grant`. *(non-negotiable — no substring/wildcard)*
6. **PKCE Verifier** recomputes `S256(code_verifier)` and compares to the stored
   `code_challenge`; mismatch ⇒ `invalid_grant`. *(non-negotiable)*
7. **Claims Assembler** loads the grant, resolves granted scopes to claims, computes the
   **pairwise `sub`** ([ADR-0010](./adr/0010-pairwise-subject-identifiers.md)), sets
   `nonce`, `acr`/`amr`, and `at_hash` for the ID token.
8. **Token Signer** builds the access-token JWT and ID-token JWT and signs each via the
   **KMS** ([ADR-0005](./adr/0005-key-custody.md)) using the active `kid`, alg pinned to
   ES256. A fresh **opaque** refresh token is created and its family row persisted.
9. **Response Builder** returns `{access_token, id_token, refresh_token, token_type,
   expires_in}` with `Cache-Control: no-store`. On any failure above, it returns the RFC
   6749 error JSON and **never** a partial token.

## Extension points

- **DPoP / mTLS sender-constraining** — the DPoP Proof Validator is the single insertion
  point; the same `cnf`/`jkt` binding flows into the Token Signer
  ([ADR-0009](./adr/0009-sender-constraining.md)).
- **PAR (RFC 9126)** — lands on the authorize side; the token endpoint only sees its
  effect (a code bound to a pushed, tamper-proof request).
- **Token Exchange (RFC 8693)** — added as an additional Grant Handler behind the same
  Request Authenticator, for delegation/impersonation use cases.
