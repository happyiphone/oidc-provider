# Abuse-Case Test Catalog

Every row of [`threat-model.md`](./threat-model.md) becomes one or more **negative tests**
that must pass (i.e. the attack must fail) before a phase ships
([`delivery-plan.md`](./delivery-plan.md)). These complement — they do not replace — the
OpenID Foundation Conformance Suite, which covers the *positive* spec behavior.

**Convention:** each test asserts the **attack is rejected** with the named error/status
and that **no token leaks**. ID format `AC-<threat>-<n>`. Phase = earliest phase where the
defended feature exists.

---

## T1 — Authorization code interception / replay

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T1-1 | A valid code already exchanged once | exchange the same code again | `400 invalid_grant`; no token | 1 |
| AC-T1-2 | A code older than its TTL (>60s) | exchange it | `400 invalid_grant` | 1 |
| AC-T1-3 | A code issued to client A | client B (or A with wrong `redirect_uri`) exchanges it | `400 invalid_grant` | 1 |
| AC-T1-4 | Code obtained without `code_verifier` | `/token` without `code_verifier` | `400 invalid_grant` | 1 |

## T11 — PKCE downgrade / absence

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T11-1 | Authorize request | omit `code_challenge` | `invalid_request`; no code issued | 1 |
| AC-T11-2 | Authorize request | `code_challenge_method=plain` | `invalid_request` | 1 |
| AC-T11-3 | Valid challenge | exchange with **wrong** `code_verifier` | `400 invalid_grant` | 1 |

## T2 / T12 — Open redirect, mix-up, redirect_uri manipulation

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T2-1 | Registered `https://rp/cb` | authorize with `https://rp/cb/../evil` | error page, **no redirect** | 1 |
| AC-T2-2 | Registered `https://rp/cb` | authorize with `https://rp.evil/cb` | error page, **no redirect** | 1 |
| AC-T2-3 | Registered exact URI | authorize with trailing `?x=` / extra segment | rejected (exact match) | 1 |
| AC-T2-4 | Unknown `client_id` | authorize | error page, **no redirect** | 1 |
| AC-T2-5 | Valid authorize | inspect success response | contains `iss` (mix-up defense) | 3 |

## T5 / T13 — CSRF on callback, session fixation

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T5-1 | Authorize without `state` (policy-required) | submit | `invalid_request` | 1 |
| AC-T5-2 | RP receives response with mismatched `state` | (RP-side contract test) | RP rejects | 1 |
| AC-T13-1 | Pre-login session id captured | complete login | session id **rotated** (differs) | 1 |

## T6 — ID token replay / forgery

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T6-1 | Authorize with `nonce=N` | decode resulting id_token | `nonce==N` present | 1 |
| AC-T6-2 | Issued id_token | verify claims | `iss`,`aud`,`exp`,`at_hash` correct; tampered token fails verify | 1 |

## T9 — JWT algorithm confusion

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T9-1 | A token with header `alg:none` | present to validation/`/userinfo` | rejected `invalid_token` | 1 |
| AC-T9-2 | A token re-signed HS256 using the public key as secret | present | rejected (alg pinned ES256) | 1 |
| AC-T9-3 | A token signed by an unknown key (`kid` not in JWKS) | present | rejected | 1 |

## T10 — JWKS poisoning

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T10-1 | `/jwks.json` served | fetch over HTTP / non-pinned | refused/upgraded; only HTTPS | 0 |
| AC-T10-2 | Rotation occurs | inspect JWKS before activation | `next` key already published | 0 |

## T3 — Access token replay

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T3-1 | Expired access token | call `/userinfo` | `401 invalid_token` | 1 |
| AC-T3-2 | DPoP-bound token + **no** proof | call `/userinfo` | `401`/`invalid_token` | 3 |
| AC-T3-3 | DPoP-bound token + proof from a **different** key | call resource | rejected | 3 |
| AC-T3-4 | DPoP proof reused (same `jti`) within window | replay | rejected | 3 |

## T4 — Refresh token theft (rotation + family reuse)

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T4-1 | Refresh token RT1 redeemed → RT2 | redeem RT1 again | `400 invalid_grant` **and family revoked** | 2 |
| AC-T4-2 | After AC-T4-1 | redeem RT2 (the "good" token) | also rejected (family revoked) | 2 |
| AC-T4-3 | Legitimate retry within leeway window | redeem RT1 twice within 15s | tolerated (idempotent), no false revoke | 2 |
| AC-T4-4 | DPoP-bound refresh token | redeem without matching proof | rejected | 3 |

## Persistence tree (c) — access after credential change

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-c-1 | Active refresh token family | user changes password | all families revoked; redeem → `invalid_grant` | 2 |
| AC-c-2 | Active session | user changes password | session invalidated globally | 2 |
| AC-c-3 | Short-lived access token outstanding | after change, within TTL | bounded by TTL; introspection reports revoked | 2 |

## T7 — Signing key compromise (process compromise drill)

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T7-1 | Full app memory dump | search for private key material | **none present** (KMS-only) | 0 |
| AC-T7-2 | Rotate `active`→`retired`, `next`→`active` | verify old + new tokens | both verify; zero downtime | 0 |

## T8 — Consent phishing / malicious client / open registration

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T8-1 | `/register` without initial access token | register | rejected by gate policy | 4 |
| AC-T8-2 | Consent screen rendered | inspect | shows client name + exact scopes; no auto-grant of new scopes | 1 |
| AC-T8-3 | Client requests scope beyond registration | authorize | `invalid_scope` | 1 |

## T14 — Clickjacking of login/consent UI

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T14-1 | Login + consent pages | inspect response headers | `CSP frame-ancestors 'none'` + `X-Frame-Options: DENY` | 1 |
| AC-T14-2 | Attempt to embed auth UI in an iframe | load cross-origin | blocked by browser | 1 |

## T15 — DoS on `/token` and `/par`

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T15-1 | Burst over per-client limit on `/token` | flood | `429` after threshold; service stays up | 3 |
| AC-T15-2 | Oversized `request`/`request_uri` object on `/par` | submit | rejected (size bound) | 3 |
| AC-T15-3 | Expired PAR `request_uri` | use at `/authorize` | `invalid_request_uri` | 3 |

## T16 — Repudiation / audit

| ID | Given | When | Then | Phase |
|---|---|---|---|---|
| AC-T16-1 | Token issuance, consent, revocation | perform each | append-only audit record with actor, client, time | 0–2 |
| AC-T16-2 | KMS signing | issue a token | KMS audit log shows the sign op | 0 |

---

## Coverage matrix (threat → tests)

| Threat | Tests | Phase first green |
|---|---|---|
| T1 | AC-T1-1..4 | 1 |
| T2/T12 | AC-T2-1..5 | 1 (T2-5 → 3) |
| T3 | AC-T3-1..4 | 1 / 3 |
| T4 | AC-T4-1..4 | 2 / 3 |
| T5/T13 | AC-T5-1..2, AC-T13-1 | 1 |
| T6 | AC-T6-1..2 | 1 |
| T7 | AC-T7-1..2 | 0 |
| T8 | AC-T8-1..3 | 1 / 4 |
| T9 | AC-T9-1..3 | 1 |
| T10 | AC-T10-1..2 | 0 |
| T11 | AC-T11-1..3 | 1 |
| T14 | AC-T14-1..2 | 1 |
| T15 | AC-T15-1..3 | 3 |
| T16 | AC-T16-1..2 | 0–2 |
| tree (c) | AC-c-1..3 | 2 |

Wire this matrix as the per-phase gate in CI: a phase cannot be marked complete until
every test whose "Phase first green" ≤ the current phase is passing.
