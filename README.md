# OIDC Provider

[![CI](https://github.com/happyiphone/oidc-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/happyiphone/oidc-provider/actions/workflows/ci.yml)
[![CodeQL](https://github.com/happyiphone/oidc-provider/actions/workflows/codeql.yml/badge.svg)](https://github.com/happyiphone/oidc-provider/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/happyiphone/oidc-provider/graph/badge.svg)](https://codecov.io/gh/happyiphone/oidc-provider)
![.NET 9](https://img.shields.io/badge/.NET-9.0-512BD4)
![OpenIddict 6.4](https://img.shields.io/badge/OpenIddict-6.4-1f6feb)
![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1-success)
![OIDC](https://img.shields.io/badge/OpenID%20Connect-Core%20%2B%20FAPI%20building%20blocks-success)

A standards-correct, security-first **OpenID Connect / OAuth 2.1 authorization server** built on
**OpenIddict 6.4 / .NET 9** — owning policy (users, MFA, consent, claims, keys) and delegating
protocol mechanics to a certified core.

## Capabilities
- **Flows**: authorization-code + PKCE (S256, mandatory), refresh (rotation + family-reuse
  revocation), client-credentials, **device** (RFC 8628), **CIBA** (poll), **token exchange**
  (RFC 8693).
- **Request/response security**: PAR (RFC 9126), DPoP (RFC 9449), **JAR + JARM** (RFC 9101),
  **mTLS-bound tokens** (RFC 8705), **Resource Indicators** (RFC 8707), **Rich Authorization
  Requests** (RFC 9396).
- **AuthN**: password (argon2id) + brute-force lockout, **TOTP**, **WebAuthn** (registration +
  passwordless/passkey-as-primary), external **federation**.
- **Logout**: RP-initiated, **back-channel** (BCL 1.0) + **front-channel** (FCL 1.0),
  **session management** (check_session_iframe).
- **Keys & tokens**: ES256 JWTs, KMS-custodied signing + 3-state rotation, pairwise subjects.
- **Lifecycle**: dynamic client registration + management (RFC 7591/7592), self-service account
  portal, browser admin console, hash-chained audit log, OpenTelemetry, Helm chart.

## Status
- ✅ **25/25** integration / abuse-case tests (CI gate) + code coverage.
- ✅ **OIDF Basic-OP** conformance plan exercised end-to-end (25 clean) — see
  [`app/conformance/RESULTS.md`](app/conformance/RESULTS.md).
- ✅ Load-measured (token + discovery), Helm + Dockerfile, k6 smoke in CI.

## Docs
| | |
|---|---|
| Implementation guide + design→code map | [`app/README.md`](app/README.md) |
| Architecture (diagrams, trust boundaries) | [`docs/oidc-provider/ARCHITECTURE.md`](docs/oidc-provider/ARCHITECTURE.md) |
| Operations runbook | [`docs/oidc-provider/RUNBOOK.md`](docs/oidc-provider/RUNBOOK.md) |
| Decisions (11 ADRs) · threat model · endpoint spec | [`docs/oidc-provider/`](docs/oidc-provider/) |
| Conformance + load tests | [`app/conformance/`](app/conformance/) · [`app/loadtest/`](app/loadtest/) |
| Security policy · contributing | [`SECURITY.md`](SECURITY.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) |

## Quick start
```bash
cd app
docker compose up --build    # Postgres + Redis + provider on http://localhost:8080
# discovery: http://localhost:8080/.well-known/openid-configuration
```
Production config (KMS, SMTP, durable DataProtection, secrets) is in the
[runbook](docs/oidc-provider/RUNBOOK.md). Default dev secrets are suffixed `-dev-only`.

> Built with [Claude Code](https://claude.com/claude-code).
