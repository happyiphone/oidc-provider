# Operations runbook

Operational procedures for the OIDC provider. Pairs with [ARCHITECTURE.md](ARCHITECTURE.md) and
the [threat model](threat-model.md).

## Configuration (production-relevant knobs)

| Key (env `Section__Key`) | Default | Production |
|---|---|---|
| `ConnectionStrings:Postgres` / `:Redis` | local dev | managed Postgres + Redis (cluster) |
| `Oidc:Issuer` | dev URL | the public HTTPS issuer (must match discovery) |
| `Oidc:Signing:Mode` | `Dev` (ephemeral ES256) | **`Kms`** + region/key |
| `Oidc:PpidKeyBase64` | dev key | **required** — pairwise-subject derivation key (KMS-wrapped) |
| `DataProtection:Store` | `FileSystem` | **`Redis`** (shared/durable cookie key-ring) |
| `Email:Mode` (+ `Email:Smtp:*`) | `Dev` (sink) | **`Smtp`** (real SES/SMTP) |
| `Oidc:Pkce:Required` | `true` | keep `true` (relax only for legacy OIDC-Basic certification) |
| `Oidc:Admin:ApiKey`, `Oidc:Registration:InitialAccessToken` | unset | strong secrets from a vault |

Fail-fast guards refuse to boot outside Development with `Signing:Mode=Dev` or a missing
`PpidKeyBase64`.

## Start / stop (local dev)
```bash
# infra: Postgres :5433, Redis :6380, local-kms :8099 (docker)
/tmp/run-oidc.sh    # provider  → :8081   (PKCE mandatory)
/tmp/run-rp.sh      # demo RP   → :5050
# reset to a clean slate:
docker exec oidc-pg psql -U oidc -d oidc -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
docker exec oidc-redis redis-cli FLUSHALL
```
Health: `/.well-known/openid-configuration` (readiness), `/health/ready` (deps), `/health/live`.

## Routine procedures
- **Key rotation**: the `KeyRotationService` worker promotes `next`→`active`→`retired` on schedule;
  verify JWKS shows the new `kid` (published before use) and old keys linger for validation until
  purge. Never delete a key still inside any unexpired token's lifetime.
- **Revoke a user (compromise)**: lock via `/admin/ui` (Lock) → sets `IsActive=false` and calls
  `RevokeAllForUserAsync` (all sessions + token families across PPIDs). Password reset does the same.
- **Revoke a client**: `/admin/ui` (Delete) or `DELETE /register/{id}` with its registration token.
- **Force global logout for a user**: `/account/logout-all` (user) or lock (admin) — fans out
  back-channel + front-channel logout to every RP the sessions joined.

## Incident response
| Symptom | Likely cause | Action |
|---|---|---|
| "Correlation failed" at RPs after deploy/restart | DataProtection ring not shared | set `DataProtection:Store=Redis`; confirm the key id is stable across instances |
| Tokens rejected everywhere after restart | Dev ephemeral signing key rotated | use `Signing:Mode=Kms` (durable keys) |
| Refresh-token reuse alert in audit | stolen/replayed refresh token | family already auto-revoked; investigate the client; rotate its secret |
| Token endpoint latency/queueing | write/CPU-bound saturation | scale out (stateless); cache KMS signing; prefer `private_key_jwt`; edge-cache discovery/JWKS |
| Discovery/JWKS errors | issuer/forwarded-headers mismatch behind proxy | ensure `UseForwardedHeaders` + correct `Oidc:Issuer` |

## Scaling & DR
- **Stateless** app → scale horizontally; all shared state is in Postgres + Redis (+ the Redis
  DataProtection ring). Edge-cache `/.well-known/*` and `/jwks` (thousands of rps, sub-ms).
- **Backups**: Postgres (clients/users/grants/audit) is the source of truth — back it up; Redis is
  ephemeral (sessions/codes) and tolerant of loss (users re-login). KMS keys are the crown jewels —
  guard custody + rotation, never export.
- The audit log is hash-chained (tamper-evident); ship it to an immutable store / SIEM.

## Verification & conformance
- CI gate: `dotnet test tests/OidcProvider.Tests` (23 abuse/flow facts) + a k6 load smoke.
- Formal: OIDF conformance suite — see [`../../app/conformance/`](../../app/conformance/) and
  `RESULTS.md` for the run, findings, and how to reproduce.
