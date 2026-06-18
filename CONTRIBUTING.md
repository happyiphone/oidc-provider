# Contributing

## Dev setup
- .NET 9 SDK, Docker (Postgres + Redis + local-kms).
- Build: `cd app && dotnet build OidcProvider.sln -c Release`
- Test: `dotnet test tests/OidcProvider.Tests` (needs `TEST_PG` / `TEST_REDIS` — see
  [`app/conformance/README.md`](app/conformance/README.md)).
- Run locally: `app/docker-compose.yml`, or the dev launch scripts in the runbook.

## Ground rules
- **Don't reimplement the protocol core** — wrap OpenIddict and own only policy (users, MFA,
  consent, claims, keys). See [ADR-0002](docs/oidc-provider/adr/0002-build-vs-buy-core.md).
- **Every protocol change needs an abuse-case test** (reused code → 400, plain PKCE → reject, etc.)
  in `tests/OidcProvider.Tests`, wired into CI.
- **Security posture changes** update [`threat-model.md`](docs/oidc-provider/threat-model.md) and/or
  an ADR.
- **Discovery metadata must match behaviour** (the OIDF suite checks this).
- **Secrets**: never commit real keys/secrets/PII. Dev placeholders are suffixed `-dev-only`.

## Workflow
Branch → PR (the template runs you through the checklist) → CI must be green (build, tests +
coverage, load smoke). Conventional, descriptive commits. CODEOWNERS review for signing/controllers/
ADR changes.

## Where things live
`docs/oidc-provider/` — ADRs, threat model, endpoint spec, architecture, runbook.
`app/src/OidcProvider.Api` — host + controllers; `app/src/OidcProvider.Core` — domain + crypto.
