# Load tests (k6)

Two workloads, three tiers each. Tiers are modelled as a **fixed arrival rate** (req/s)
via k6's `constant-arrival-rate` executor, so we observe latency/error behaviour *at* a
target throughput and can see exactly where the server saturates.

```bash
# token endpoint (client_credentials — the write/sign hot path)
k6 run -e TIER=medium   loadtest/token.js
k6 run -e TIER=high     loadtest/token.js
k6 run -e TIER=realhigh loadtest/token.js

# read path (discovery + JWKS — cacheable, no DB write)
k6 run -e TIER=medium   loadtest/discovery.js
k6 run -e TIER=high     loadtest/discovery.js
k6 run -e TIER=realhigh loadtest/discovery.js

# override target: -e BASE=https://idp.example
```

| Workload | Tier | Target rps | Duration |
|---|---|---|---|
| token | medium / high / realhigh | 200 / 1 000 / 5 000 | 30s |
| read  | medium / high / realhigh | 1 000 / 5 000 / 15 000 | 20s |

Thresholds (pass/fail gates) are encoded in each script: `http_req_failed` rate and
`http_req_duration` p95, loosened for `realhigh` because that tier is meant to *find* the
ceiling, not assert it stays fast.

## Observed results

Measured on the dev box (12-core macOS, single `dotnet run -c Release` instance, **dev
in-process ES256 signing** — not KMS, Postgres + Redis in Docker, **k6 co-located on the
same machine** so it competes for CPU). Treat as relative shape, not production capacity.

### Token endpoint (`client_credentials`)

| Tier | Target | Achieved rps | p95 latency | HTTP errors | Notes |
|---|---|---|---|---|---|
| medium   | 200   | **200**  | **17 ms**  | 0% | comfortable headroom |
| high     | 1 000 | ~508 | 4.05 s | 0% | saturated; ~13.6k iterations dropped |
| realhigh | 5 000 | ~476 | 12.3 s | 0% | saturated; ~132k dropped |

**Ceiling ≈ 500 req/s** for token issuance on a single dev instance. Note **0 HTTP
failures even when saturated** — excess load *queues* (latency climbs) rather than
erroring. The cost per request is dominated by: (1) per-request **client-secret
verification** (hash compare), (2) **per-token Postgres write** (OpenIddict persists the
authorization + token), (3) in-process ES256 signing.

### Read path (discovery + JWKS)

| Tier | Target | Achieved rps | p95 latency | HTTP errors |
|---|---|---|---|---|
| medium   | 1 000  | **1 000**  | **1 ms**   | 0% |
| high     | 5 000  | **5 000**  | **187 µs** | 0% |
| realhigh | 15 000 | ~3 030 | 2.8 s | 5.9% |

The read path sustains **5 000 rps at sub-millisecond p95**. It only buckles at 15 000 rps
— and there the limiter is the box itself (k6 generating 15k rps + the server share 12
cores), not the provider logic.

## What this tells you (and production tuning)

The token endpoint is **write/CPU-bound**, the read path is effectively free. To raise the
token ceiling in production:

1. **Scale horizontally.** The app is stateless (sessions/codes in Redis, tokens in
   Postgres) — put N instances behind a load balancer. Throughput scales ~linearly until
   the datastore is the bottleneck.
2. **Don't persist `client_credentials` access tokens.** They're short-lived and
   re-mintable; skipping the DB write removes the dominant per-request cost. (OpenIddict
   can disable token storage for selected flows.)
3. **Prefer `private_key_jwt` over client secrets** (ADR-0008) — avoids the per-request
   secret-hash, replacing it with a signature verify (cacheable client keys).
4. **KMS signing with a connection pool + short-lived data-key caching** (ADR-0005) — in
   prod the KMS round-trip replaces in-proc signing; pool it and co-locate the region.
5. **Output-cache discovery + JWKS** at the edge/CDN (they're public and slow-changing) —
   takes the highest-fan-out endpoints off the app entirely.
6. **Tune Postgres**: connection pool size, `synchronous_commit`, and a dedicated token
   table with the indexes the rotation/reuse queries need (see `../../docs/oidc-provider/schema.sql`).

## Caveats

- Single instance, dev signing, k6 on the same host → absolute numbers understate a
  real deployment. The **relative** picture (read path ~10× the token path; token path
  queues rather than errors under overload) is the takeaway.
- Each token-tier run writes many rows to Postgres; truncate or reset the DB between
  serious runs (`docker exec oidc-pg psql -U oidc -d oidc -c "TRUNCATE ..."`).

## Measured (local, 2026-06-18 — Mac, single instance, dev ES256 signing)

k6 v1.7 against the running provider:

| Endpoint | Arrival rate | p95 | avg | errors | checks |
|---|---|---|---|---|---|
| **/token** (client_credentials — auth + ES256 sign + persist) | 200 req/s × 30s | **18.3 ms** | 17.4 ms | **0%** (0/6001) | 100% (12002) |
| **/.well-known/openid-configuration** (read path) | 1000 req/s × 20s | **412 µs** | 350 µs | **0%** (0/20000) | 100% |

Take-away: the read path is sub-millisecond and cache-friendly (edge-cache discovery/JWKS for
thousands of rps); the token hot path holds 200 rps at ~18 ms p95 with a single dev instance and
zero errors — scale it horizontally (stateless) for higher tiers (`TIER=high|realhigh`).
