# OIDC Provider — Reference Implementation (.NET 8 + OpenIddict)

A runnable scaffold of the architecture in [`../docs/oidc-provider/`](../docs/oidc-provider/).
It wires OpenIddict (the certified protocol core, [ADR-0002](../docs/oidc-provider/adr/0002-build-vs-buy-core.md))
to the custom policy this design owns: login/MFA, consent, pairwise subjects, refresh-token
family revocation, KMS-backed signing, and 3-state key rotation.

> **Status: compiled, run, and behaviourally verified.** Targets **.NET 9** +
> **OpenIddict 6.4** + **EF Core 9**. Builds clean (0 warnings / 0 errors), boots against
> Postgres + Redis, and passes a live end-to-end flow, the security gates, the new
> PAR/TOTP-MFA flows, and a k6 load suite — all listed below.

## Verified behaviour (live HTTP)

Driven against a running instance (login → consent → code → token → userinfo):

| Check | Result |
|---|---|
| Discovery + JWKS (ES256, `kid` published) | ✅ |
| Auth Code + PKCE happy path → ES256 JWT access + id tokens | ✅ |
| `id_token`: correct `iss`/`aud`/`nonce`/`acr`/`amr`, **pairwise `sub`** = userinfo `sub` | ✅ |
| Callback carries `iss` (mix-up defense, T2) | ✅ |
| AC-T1-1 reused authorization code → `invalid_grant` | ✅ |
| AC-T11-1 missing `code_challenge` → `400 invalid_request`, no code | ✅ |
| AC-T11-2 `code_challenge_method=plain` → rejected | ✅ |
| AC-T11-3 wrong PKCE `code_verifier` → `invalid_grant` | ✅ |
| AC-T2-1 unregistered `redirect_uri` → `400`, **no redirect to attacker** | ✅ |
| AC-T4 refresh rotation RT1→RT2 | ✅ |
| AC-T4-1 reused (rotated-out) refresh token → `invalid_grant` | ✅ |
| AC-T4-2 reuse triggers **family-wide revocation** (RT2 also dead) | ✅ |
| AC-T4-3 retry within reuse-leeway window tolerated | ✅ (observed) |
| **TOTP MFA step-up** (bob): RFC 6238 verify → `acr=urn:acr:mfa`, `amr=[pwd,otp]` | ✅ |
| **PAR (RFC 9126)**: `POST /par` → `request_uri` → authorize → tokens | ✅ |
| **Client credentials** grant (machine client) | ✅ |
| **EF migration** (`Initial`) applies to a fresh DB (production path) | ✅ |
| **Load suite** (k6): token ~500 rps ceiling, read path 5 000 rps @ p95 187µs | ✅ ([loadtest/](./loadtest/README.md)) |
| **WebAuthn/FIDO2** assertion (carol): verified → `acr=urn:acr:mfa`, `amr=[pwd,webauthn]` | ✅ |
| WebAuthn **clone detection** (stale signCount rejected) | ✅ |
| **Razor UI** (login/MFA/consent) with **antiforgery**; missing token → `400` | ✅ |
| **Integration/abuse suite** (`dotnet test`, 9 facts) — the CI gate | ✅ all pass |
| **WebAuthn registration** (attestation, fmt=none): enroll → assert roundtrip at runtime | ✅ |
| **HTTPS issuer** behind nginx (`UseForwardedHeaders`): `https://host.docker.internal:9443/` | ✅ |
| **OIDF conformance suite** built + run (1088 modules); fetches provider discovery/JWKS over trusted HTTPS | ✅ |
| OIDF run surfaced + **fixed** a metadata bug (advertised `plain` PKCE → now `S256` only) | ✅ |

## Run it (dev)

```bash
cd app
docker compose up --build      # Postgres + Redis + API on http://localhost:8080
```

Dev mode uses an **ephemeral ES256 signing key** (rotates on restart) so the stack boots
with no cloud dependency. Schema is created via `EnsureCreated`. A demo client and user
are seeded:

- client `demo-web` / secret `demo-secret-dev-only`, redirect `http://localhost:5000/callback`
- user `alice` / `password123!`

Discovery: `http://localhost:8080/.well-known/openid-configuration` ·
JWKS: `http://localhost:8080/jwks` (served by OpenIddict).

## Project layout

```
app/
├── docker-compose.yml · Dockerfile
├── OidcProvider.sln
└── src/
    ├── OidcProvider.Core/         class library — domain + data + crypto
    │   ├── Entities/Entities.cs            users, MFA, PPID map, consent, keys, audit
    │   ├── Data/AuthDbContext.cs           EF + UseOpenIddict() + invariants/indexes
    │   ├── Services/DomainServices.cs      PPID, ACR policy, consent, sessions, users
    │   └── Signing/                        key store, KMS adapter, token-family facade
    └── OidcProvider.Api/          ASP.NET Core host
        ├── Program.cs                      all wiring (OpenIddict server/validation, DI)
        ├── Signing/SigningSetup.cs         Dev vs KMS signing credentials
        ├── Controllers/                    Authorize, Token, UserInfo, Account (login/MFA)
        ├── Worker/                         RefreshReuseHandler, KeyRotationService
        └── DbSeeder.cs
```

## Design → code map

| Decision | Enforced in |
|---|---|
| OAuth 2.1, no implicit/ROPC ([ADR-0001](../docs/oidc-provider/adr/0001-protocol-baseline.md)) | `Program.cs` — only `AllowAuthorizationCodeFlow/RefreshToken/ClientCredentials` |
| PKCE S256 mandatory ([ADR-0011](../docs/oidc-provider/adr/0011-pkce-s256-mandatory.md)) | `RequireProofKeyForCodeExchange()` + guard in `AuthorizeController` |
| JWT ES256 access tokens ([ADR-0004](../docs/oidc-provider/adr/0004-token-format.md)) | `DisableAccessTokenEncryption()` + ES256 signing key |
| KMS key custody + rotation ([ADR-0005](../docs/oidc-provider/adr/0005-key-custody.md)) | `Signing/Signing.cs`, `SigningSetup.cs`, `Worker/KeyRotationService.cs` |
| Redis/Postgres split ([ADR-0006](../docs/oidc-provider/adr/0006-storage-split.md)) | `RedisUserSession` + `AuthDbContext` |
| Refresh rotation + family revoke ([ADR-0007](../docs/oidc-provider/adr/0007-refresh-token-rotation.md)) | `UseReferenceRefreshTokens()` + `RefreshReuseHandler` + `TokenFamilyFacade` |
| Pairwise PPID ([ADR-0010](../docs/oidc-provider/adr/0010-pairwise-subject-identifiers.md)) | `PairwiseSubjects` + `AuthorizeController` |
| Clickjacking defense (T14) | CSP/`X-Frame-Options` middleware in `Program.cs` |
| Anti-fixation (T13) | fresh session id per login in `AccountController` |

## What's real vs. stubbed

**Real:** flow restriction, PKCE enforcement, exact-redirect (OpenIddict), JWT/ES256,
pairwise subjects, consent capture, the refresh-reuse→family-revocation path, the KMS
signing adapter, the 3-state rotation worker, security headers, password hashing.

**Now implemented:**
- **TOTP MFA** — real RFC 6238 verifier (`Core/Services/Totp.cs`); user `bob` enrolled →
  step-up yields `acr=urn:acr:mfa` / `amr=[pwd,otp]`.
- **WebAuthn / FIDO2** — real assertion verifier (`Core/Services/WebAuthn.cs`): challenge
  binding, `rpIdHash`/UP flag, ES256 signature over `authData‖SHA256(clientDataJSON)`, and
  **signCount clone detection**. User `carol` enrolled (`/account/webauthn/options` +
  `/account/webauthn`); verified end to end with a software authenticator →
  `amr=[pwd,webauthn]`. *Registration/attestation* is out of scope (use Fido2NetLib in
  prod — attestation validation is the library-worthy part); credentials are seeded.
- **PAR (RFC 9126)** — `/par` enabled and exercised end to end.
- **Razor UI** — login / MFA / consent are server-rendered Razor views with **antiforgery
  tokens** (consent POST validated → `400` without a token).
- **EF migrations** — `Initial` committed under `Core/Data/Migrations`; production path
  (`MigrateAsync`) verified on a fresh DB. Dev uses `EnsureCreated`.
- **Tests + CI** — `tests/OidcProvider.Tests` (9 in-proc integration/abuse facts) is the
  gate; [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs build + tests + a k6
  smoke. See [`conformance/`](./conformance/README.md) for the formal OIDF suite wiring.

**WebAuthn registration** — the attestation (`navigator.credentials.create`) ceremony is now
implemented (`Core/Services/WebAuthn.cs`, CBOR via `System.Formats.Cbor`): parses the
attestation object, validates `rpIdHash`/AT flag/challenge/origin, extracts the COSE EC2
P-256 key, and enrolls the credential. Verified at runtime: register → assert roundtrip with
a software authenticator. Supports `fmt="none"`/self-attestation (passkey/2FA norm);
validating packed/tpm/etc. attestation against the FIDO MDS should use Fido2NetLib in prod.

**OIDF conformance suite** — actually built and run (see [`conformance/`](./conformance/README.md)):
provider TLS-fronted to an HTTPS issuer, dev CA trusted by the suite, suite fetched
discovery/JWKS over trusted HTTPS, and the run found+fixed a real metadata bug. A fully
green **Basic OP** certification still needs interactive browser login/consent (an
operational step), documented in `conformance/`.

**Still deferred (only this):**
- **DPoP** ([ADR-0009](../docs/oidc-provider/adr/0009-sender-constraining.md)) — **not**
  wired: OpenIddict (through 7.x) exposes no first-class DPoP server toggle, so doing it
  right means custom handlers (or mTLS-bound tokens). Left an honest hook, not a hand-rolled
  approximation. Its companion PAR *is* done.

## Version notes (OpenIddict 6.4 / .NET 9 / EF Core 9)

Version-sensitive bits, pinned to the 6.4 surface (these names shift between majors — 6.4
differs from 5.8):
- Endpoint setters: `SetUserInfoEndpointUris` (capital I), `SetEndSessionEndpointUris`
  ("end-session", not "logout"), `SetPushedAuthorizationEndpointUris` (PAR);
  passthrough: `EnableUserInfoEndpointPassthrough`, `EnableEndSessionEndpointPassthrough`.
- `GetOpenIddictServerRequest()` lives in the `Microsoft.AspNetCore` namespace.
- Prompt handling is `request.HasPromptValue("none")` / `"login"`.
- A client must hold `Permissions.Endpoints.PushedAuthorization` to use `/par`.
- Signing/encryption keys are injected via **`IConfigureOptions<OpenIddictServerOptions>`**
  (an `IPostConfigureOptions` runs *after* OpenIddict's own validating post-configure and
  fails with "no encryption key").
- Dev HTTP needs `UseAspNetCore().DisableTransportSecurityRequirement()` (Development only).
- The refresh-reuse handler reads `context.RefreshTokenPrincipal.GetTokenId()`.

## Conformance & tests

Wire the [OpenID Foundation Conformance Suite](https://openid.net/certification/) and the
abuse-case catalog ([`../docs/oidc-provider/abuse-case-tests.md`](../docs/oidc-provider/abuse-case-tests.md))
into CI as the acceptance gate per [`delivery-plan.md`](../docs/oidc-provider/delivery-plan.md).
Each `AC-*` row maps to a concrete negative test (reused code → 400, `alg:none` → reject,
reused refresh token → family revoked, …).
```
