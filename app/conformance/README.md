# Conformance testing

Two layers, fast → formal:

## 1. In-repo gate (runs in CI, every push) — `dotnet test`

`tests/OidcProvider.Tests` boots the real app in-process (`WebApplicationFactory`) against
Postgres + Redis and asserts the happy paths **and** the abuse cases from
[`../../docs/oidc-provider/abuse-case-tests.md`](../../docs/oidc-provider/abuse-case-tests.md):
discovery/JWKS shape, auth-code+PKCE issuance, pairwise `sub` = userinfo `sub`, reused code
→ `invalid_grant`, missing/`plain` PKCE rejected, wrong verifier rejected, unregistered
`redirect_uri` → no redirect, and refresh **rotation + family-reuse revocation**. This is
the gate wired into [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) (plus a k6
load smoke). Fast, deterministic, no external services beyond the DB/cache.

```bash
# locally, against the dev containers (Postgres 5433 / Redis 6380):
TEST_PG="Host=localhost;Port=5433;Database=oidc_test;Username=oidc;Password=oidc_dev_only" \
TEST_REDIS="localhost:6380" \
dotnet test tests/OidcProvider.Tests/OidcProvider.Tests.csproj
```

## 2. Formal gate — OpenID Foundation Conformance Suite

The objective definition of "correct" ([delivery-plan](../../docs/oidc-provider/delivery-plan.md)):
the official [OIDF conformance suite](https://gitlab.com/openid/conformance-suite) — a
separate Java app (server + nginx + MongoDB).

### What was actually run here

The suite was built from source (`mvn package` → `fapi-test-suite.jar`) and brought up
via its own compose (**1088 test modules loaded**, UI on `https://localhost.emobix.co.uk:8443`).
The provider was TLS-fronted (nginx, `https://host.docker.internal:9443`, `X-Forwarded-*`
honored so the discovery `issuer` is correct), and the dev CA was imported into the suite
server's JVM truststore (`USE_SYSTEM_CA_CERTS=1` + a mount under `/certificates`). Verified
end to end:

- `openssl s_client` from inside the suite server → provider: **`Verify return code: 0 (ok)`**.
- The suite server fetched the provider's **discovery + JWKS over trusted HTTPS** (no `-k`):
  correct `issuer`, endpoints, `jwks` (EC/ES256/P-256), and PAR endpoint.
- This surfaced a real metadata bug — discovery advertised `code_challenge_methods_supported:
  ["plain","S256"]`, contradicting [ADR-0011](../../docs/oidc-provider/adr/0011-pkce-s256-mandatory.md).
  **Fixed** (removed `plain`); the suite now sees `["S256"]`.

### What remains (operational, not a code gap)

A fully green **Basic OP** certification run needs (a) per-test static client/redirect
registration matching the suite's callback, and (b) **interactive browser login + consent** —
OP profiles require a human (or a driven browser) to complete the authentication step; the
suite cannot perform the end-user login itself. That's a manual/CI-with-browser step, run
against this now-reachable HTTPS issuer. Wiring for it:

1. Clone + start the suite (its own compose):
   ```bash
   git clone https://gitlab.com/openid/conformance-suite.git
   cd conformance-suite
   docker compose up -d        # serves the test UI/API on https://localhost:8443
   ```
2. Start this provider reachable from the suite (HTTPS in front — the suite requires it;
   put the provider behind a TLS reverse proxy, since dev HTTP is local-only).
3. Create a test plan for **`oidcc-basic-certification-test-plan`** using
   [`oidc-basic-config.json`](./oidc-basic-config.json) (edit issuer/client to match your
   deployment). Run headless via the suite's REST API, or interactively in its UI.
4. Target profiles by phase (see delivery-plan): Basic OP → then config/refresh →
   then FAPI-adjacent (PAR). Each phase is "done" when its profile is green here.

### TLS-fronting recap (how the HTTPS issuer was produced)

`nginx` terminates TLS on `:9443` with a dev-CA-signed cert (SAN includes
`host.docker.internal`) and proxies to the provider on `:8081`, setting
`X-Forwarded-Proto/Host`. The app honors these via `UseForwardedHeaders`, so the
request-derived `issuer` becomes `https://host.docker.internal:9443/` while direct
`http://127.0.0.1:8081` keeps its own issuer. In production this is your real ingress +
ACME/managed cert, not a dev CA.
