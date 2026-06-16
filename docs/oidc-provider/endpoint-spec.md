# Endpoint Specification — OIDC Provider (OAuth 2.1 + OIDC Core 1.0)

Request parameters, validation rules, and error responses per endpoint. Error codes are
the RFC 6749 / OIDC set: `invalid_request`, `invalid_client`, `invalid_grant`,
`unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, `access_denied`,
`invalid_token`, `insufficient_scope`. All token-bearing responses send
`Cache-Control: no-store`.

---

## `GET` / `POST /authorize` — Authorization Endpoint

**Purpose:** Begin user authentication + authorization; issue an authorization code.
**Spec:** OIDC Core 1.0 §3.1, OAuth 2.1.

| Param | Required | Validation |
|---|---|---|
| `response_type` | yes | Must be `code` (implicit/hybrid not supported) |
| `client_id` | yes | Must resolve to a registered client |
| `redirect_uri` | yes | **Exact** match against a registered URI (no wildcard/substring) |
| `scope` | yes | Must include `openid`; each scope registered for client |
| `state` | yes* | Opaque CSRF token; echoed back verbatim (*required by policy) |
| `nonce` | yes* | Bound into ID token; replay defense (*required for `openid`) |
| `code_challenge` | yes | PKCE challenge — **mandatory for all clients** |
| `code_challenge_method` | yes | Must be `S256` (`plain` rejected) |
| `prompt` | no | `none`/`login`/`consent`/`select_account`; `none` ⇒ no UI |
| `max_age` | no | Max auth age in seconds; forces re-auth if exceeded |
| `acr_values` | no | Requested authentication context (e.g. MFA) |
| `login_hint` | no | Pre-fill identifier |
| `request` / `request_uri` | no | Signed request object (JAR) / PAR reference |

**Success:** `302` redirect to `redirect_uri` with `code` + `state` (or pushed via PAR).
**Errors** (returned to `redirect_uri` if URI valid, else shown to user):

| Error | When | Delivery |
|---|---|---|
| `invalid_request` | missing/duplicate param, bad PKCE | redirect or page |
| `unauthorized_client` | client may not use `code` | redirect |
| `invalid_scope` | unknown/forbidden scope | redirect |
| `access_denied` | user declines consent / `prompt=none` needs login | redirect |
| (no redirect) | `redirect_uri` mismatch or `client_id` invalid | **error page, never redirect** |

---

## `POST /par` — Pushed Authorization Request

**Purpose:** Client pushes authorization params over the back channel; gets a
`request_uri` to use at `/authorize`. **Spec:** RFC 9126.

| Param | Required | Validation |
|---|---|---|
| (authorize params) | yes | Same validation as `/authorize`, server-side |
| client authentication | yes | Per [ADR-0008](./adr/0008-client-authentication.md) |
| `request_uri` | — | **Must not** be present in the PAR request |

**Success:** `201` `{ "request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 60 }`.
**Errors:** `invalid_request` (400), `invalid_client` (401). `request_uri` is single-use,
short TTL (stored in Redis per [ADR-0006](./adr/0006-storage-split.md)).

---

## `POST /token` — Token Endpoint

**Purpose:** Exchange a grant for tokens. **Spec:** OAuth 2.1 / OIDC Core. See the
[component design](./component-token-endpoint.md) for the pipeline.

| Param | Required | Validation |
|---|---|---|
| `grant_type` | yes | `authorization_code` \| `refresh_token` \| `client_credentials` \| `urn:ietf:params:oauth:grant-type:device_code` |
| `code` | code grant | Single-use, unexpired, bound to client |
| `redirect_uri` | code grant | **Exact** match to the one used at `/authorize` |
| `code_verifier` | code grant | `S256` must equal stored `code_challenge` |
| `refresh_token` | refresh grant | Active, not rotated-out (else family revoked) |
| `scope` | optional | Subset of originally granted scope |
| `device_code` | device grant | Valid, approved, not expired |
| client auth | confidential | `private_key_jwt` preferred; `DPoP` header optional/required |

**Success:** `200` `{ access_token, token_type, expires_in, id_token?, refresh_token?, scope? }`.

| Error | When | Status |
|---|---|---|
| `invalid_request` | malformed/missing param | 400 |
| `invalid_client` | client auth fails | 401 |
| `invalid_grant` | bad/expired/replayed code or refresh token, `redirect_uri` mismatch, PKCE fail | 400 |
| `unauthorized_client` | grant not allowed for client | 400 |
| `unsupported_grant_type` | unknown `grant_type` | 400 |
| `invalid_scope` | scope exceeds grant | 400 |
| `authorization_pending` / `slow_down` | device flow not yet approved | 400 |

---

## `GET /userinfo` — UserInfo Endpoint

**Purpose:** Return claims for the authenticated user. **Spec:** OIDC Core §5.3.
**Auth:** `Authorization: Bearer <token>` or `DPoP <token>` + `DPoP` proof.

**Success:** `200` JSON claims (or signed/encrypted JWT if client configured). `sub`
**must** match the ID token's `sub` (pairwise per client).

| Error | When | Status / header |
|---|---|---|
| `invalid_token` | expired/invalid/revoked access token | 401 `WWW-Authenticate` |
| `insufficient_scope` | token lacks scope for requested claims | 403 |
| `invalid_request` | malformed auth header | 400 |

---

## `GET /.well-known/openid-configuration` — Discovery

**Purpose:** Publish provider metadata. **Spec:** OIDC Discovery 1.0 / RFC 8414.
**Success:** `200` JSON: `issuer`, `authorization_endpoint`, `token_endpoint`,
`userinfo_endpoint`, `jwks_uri`, `pushed_authorization_request_endpoint`,
`registration_endpoint`, `scopes_supported`, `response_types_supported` (`["code"]`),
`grant_types_supported`, `code_challenge_methods_supported` (`["S256"]`),
`token_endpoint_auth_methods_supported`, `dpop_signing_alg_values_supported`,
`subject_types_supported` (`["pairwise","public"]`), `id_token_signing_alg_values_supported`
(`["ES256"]`). Publicly cacheable. No auth.

---

## `GET /jwks.json` — JSON Web Key Set

**Purpose:** Publish **public** signing keys for token verification. **Spec:** RFC 7517.
**Success:** `200` `{ "keys": [ {kty, crv, x, y, kid, use:"sig", alg:"ES256"}, ... ] }`.
Includes `active`, `retired`-but-unexpired, **and the `next` key pre-published before
first use** so verifiers prefetch it ([ADR-0005](./adr/0005-key-custody.md)). Public,
short cache TTL to bound rotation propagation. No auth.

---

## `POST /introspect` — Token Introspection

**Purpose:** Resource server queries token validity/metadata. **Spec:** RFC 7662.
**Auth:** caller (resource server / client) must authenticate.

| Param | Required | Validation |
|---|---|---|
| `token` | yes | The token to introspect |
| `token_type_hint` | no | `access_token` \| `refresh_token` |

**Success:** `200` `{ "active": true, sub, scope, client_id, exp, iat, cnf? }`, or
`{ "active": false }` for invalid/expired/revoked. **Errors:** `invalid_client` (401).
Never reveal metadata to an unauthenticated caller.

---

## `POST /revoke` — Token Revocation

**Purpose:** Client revokes a token it owns. **Spec:** RFC 7009.

| Param | Required | Validation |
|---|---|---|
| `token` | yes | Token to revoke; must belong to the authenticating client |
| `token_type_hint` | no | `access_token` \| `refresh_token` |

**Success:** `200` (idempotent — returns `200` even if already invalid/unknown).
Revoking a refresh token **revokes its whole family**. **Errors:** `invalid_client` (401).

---

## `POST /register` — Dynamic Client Registration

**Purpose:** Programmatically register a client. **Spec:** RFC 7591 (+ 7592 management).

| Param | Required | Validation |
|---|---|---|
| `redirect_uris` | yes (for code) | Absolute HTTPS URIs (loopback/custom-scheme for native) |
| `token_endpoint_auth_method` | yes | `private_key_jwt` \| `client_secret_*` \| `none` |
| `grant_types` | yes | Subset of supported; must pair with `response_types` |
| `jwks` / `jwks_uri` | if asymmetric auth | Valid key set |
| `client_name`, `scope`, `contacts`, `logo_uri` | no | Metadata |

**Success:** `201` `{ client_id, client_secret?, registration_access_token, ... }`.
**Errors:** `invalid_redirect_uri`, `invalid_client_metadata` (400). Gate behind an
initial access token / approval policy to prevent open registration abuse.

---

## `GET /device_authorization` + device flow — *(brief)*

**Spec:** RFC 8628. Client `POST`s to the device authorization endpoint → receives
`device_code`, `user_code`, `verification_uri`, `interval`. User visits
`verification_uri`, enters `user_code`, authenticates + consents. Client polls `/token`
with `grant_type=device_code`, receiving `authorization_pending` / `slow_down` until
approval, then tokens. Use for input-constrained devices (TVs, CLIs).

---

## `GET /logout` — RP-Initiated Logout + channel logout — *(brief)*

**Spec:** OIDC RP-Initiated Logout + Session Management / Front-Channel + Back-Channel
Logout. Params: `id_token_hint`, `post_logout_redirect_uri` (must be registered),
`state`. Ends the provider session and propagates logout: **front-channel** via iframes
to each client's `frontchannel_logout_uri`, **back-channel** via a signed logout token
POSTed to each `backchannel_logout_uri`. Redirects to `post_logout_redirect_uri` if
registered and valid.
