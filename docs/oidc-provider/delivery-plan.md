# Phased Delivery Plan — OIDC Provider

C#/.NET wrapping a certified core (OpenIddict-style — see
[`adr/0002`](./adr/0002-build-vs-buy-core.md), [`adr/0003`](./adr/0003-language-runtime.md)),
targeting OAuth 2.1 + OpenID Connect Core 1.0.

## Strategy

Ship the **smallest spec-correct provider first**, then layer security and interop
features in dependency order. Every phase has a hard, objective acceptance gate:

> **The relevant subset of the [OpenID Foundation Conformance Suite](https://openid.net/certification/)
> passes in CI, AND the abuse-case suite for that phase is green** (one negative test per
> applicable row of [`threat-model.md`](./threat-model.md)).

No phase is "done" on demo; it is done on conformance + abuse-case green. Phases are
sequenced by dependency, not calendar dates.

---

## Phase 0 — Foundations

**Goal:** the scaffolding that everything else depends on, with the conformance harness
wired from day one (even while mostly red).

**Scope:**
- Repo, CI/CD, IaC, container build, SBOM + dependency scanning.
- **KMS/HSM key management** ([`adr/0005`](./adr/0005-key-custody.md)): generate signing
  keys in KMS, three-state lifecycle (`next`/`active`/`retired`), publish `/jwks.json`
  with **`next` key pre-rotation**.
- **PostgreSQL + Redis** provisioned with the storage split
  ([`adr/0006`](./adr/0006-storage-split.md)).
- **Conformance harness** running in CI against a stub OP (mostly failing — that's fine).
- Structured **audit logging** + observability (traces/metrics) from the first commit.

**Out of scope:** any real grant flow.
**Exit criteria:** JWKS publishes a valid, rotating key set; conformance suite executes
in CI and reports; key-rotation drill (`next`→`active`→`retired`) succeeds with zero
verification downtime.
**Risks:** KMS latency on the signing path; getting `next`-key pre-publication right
early (cheap now, expensive later).

---

## Phase 1 — MVP (Basic OP)

**Goal:** a minimal, spec-correct provider that real clients can integrate against.

**Scope:**
- **Authorization Code + PKCE** (S256, mandatory — [`adr/0001`](./adr/0001-protocol-baseline.md)).
- Endpoints: `/authorize`, `/token`, `/userinfo`, Discovery, `/jwks.json`
  (see [`endpoint-spec.md`](./endpoint-spec.md)).
- **Exact `redirect_uri`** matching; mandatory `state` + `nonce`.
- **ES256-signed** ID tokens and JWT access tokens
  ([`adr/0004`](./adr/0004-token-format.md)).
- Server-rendered login + consent UI with CSP `frame-ancestors 'none'`.

**Out of scope:** refresh tokens, PAR, DPoP, dynamic registration, device flow, logout.
**Exit criteria:** **OIDC "Basic OP" conformance profile passes**; abuse tests T1, T2,
T5, T6, T9, T11, T12, T14 green.
**Risks:** consent/login UX correctness; `at_hash` and pairwise `sub` edge cases.

---

## Phase 2 — Token lifecycle & client authentication

**Goal:** production-grade token management and confidential clients.

**Scope:**
- **Refresh token rotation + family reuse detection**
  ([`adr/0007`](./adr/0007-refresh-token-rotation.md)) with a retry grace window.
- `/revoke` (RFC 7009, family-wide) and `/introspect` (RFC 7662).
- **`private_key_jwt`** client authentication
  ([`adr/0008`](./adr/0008-client-authentication.md)); `client_secret_*` legacy-only.
- Consent management (view/revoke granted consents); credential-change → global
  token-family revocation.

**Out of scope:** sender-constraining, federation.
**Exit criteria:** OIDC **"Config + Dynamic"-adjacent** token tests + revocation/
introspection conformance pass; abuse tests T4 and persistence tree (c) green.
**Risks:** rotation race conditions under client retries; introspection authZ.

---

## Phase 3 — Hardening & sender-constraining

**Goal:** full RFC 9700 BCP compliance and theft-resistant tokens.

**Scope:**
- **PAR** (RFC 9126) and **DPoP** (RFC 9449) —
  [`adr/0009`](./adr/0009-sender-constraining.md).
- **`iss`** in authorization responses (mix-up defense).
- **Pairwise PPID** subjects by default
  ([`adr/0010`](./adr/0010-pairwise-subject-identifiers.md)).
- Rate limiting on `/token` and `/par`; request-object size bounds.

**Out of scope:** optional FAPI stretch (Phase 4).
**Exit criteria:** **FAPI-adjacent** conformance (PAR + DPoP) passes; full RFC 9700
checklist satisfied; abuse tests T3, T10, T15 green.
**Risks:** DPoP clock-skew / replay-cache tuning; PAR/`request_uri` TTL correctness.

---

## Phase 4 — Interop & extras

**Goal:** ecosystem breadth.

**Scope:**
- **Dynamic client registration** (RFC 7591) behind a gated approval policy.
- **Device Authorization flow** (RFC 8628).
- **RP-Initiated + front/back-channel logout** (OIDC Session Management).
- **Federation** to external IdPs (social / enterprise OIDC/SAML).
- **FAPI 2.0** profile — *optional / stretch*.

**Out of scope:** anything not driven by a concrete consumer need.
**Exit criteria:** dynamic-registration + device + logout conformance profiles pass;
FAPI 2.0 if pursued.
**Risks:** open-registration abuse (gate it — T8); logout propagation reliability.

---

## Conformance & testing strategy

1. **OIDF Conformance Suite per phase** — each phase targets a named profile; the build
   fails if its profile regresses. This is the objective definition of "correct."
2. **Abuse-case suite** — every row of [`threat-model.md`](./threat-model.md) becomes a
   negative test: a reused code *must* 400, a substring `redirect_uri` *must* be rejected,
   `alg:none` *must* be refused, a reused refresh token *must* revoke its family, etc.
3. **Load testing** of `/token` and `/par` (including KMS-signing throughput) before each
   production milestone — T15.
4. **Key-rotation drills** — scheduled `next`→`active`→`retired` rotations exercised in
   staging with live verifiers, proving zero-downtime ([`adr/0005`](./adr/0005-key-custody.md)).

## Milestone summary

| Phase | Headline deliverable | Conformance profile | Sequence |
|---|---|---|---|
| 0 | KMS + JWKS rotation, CI harness | (harness wired) | first |
| 1 | Auth Code + PKCE MVP | **Basic OP** | after 0 |
| 2 | Refresh rotation, revoke/introspect, `private_key_jwt` | token + revocation/introspection | after 1 |
| 3 | PAR + DPoP + PPID + RFC 9700 | **FAPI-adjacent** | after 2 |
| 4 | DynReg, device, logout, federation | dynreg / device / logout (+ FAPI 2.0 opt) | last |
