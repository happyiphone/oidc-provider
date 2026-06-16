# 6. Storage split: Redis (ephemeral, TTL) + PostgreSQL (durable)

**Status:** Accepted

## Context

The provider has two very different data shapes. **Ephemeral, high-churn, security-
critical** items — authorization codes, PAR request objects, login sessions, nonces —
must be single-use and short-lived; leaving them in a durable store risks replay if TTL
enforcement is sloppy and adds write amplification. **Durable** items — client
registrations, user accounts, grants, consents, refresh-token families — need
transactional integrity, relational queries, and long-term persistence.

## Decision

- **Redis** holds ephemeral artifacts with **strict server-enforced TTLs**: auth codes
  (≤60s, single-use — deleted on consumption), PAR `request_uri` payloads, sessions,
  replay-prevention nonces.
- **PostgreSQL** holds durable, relational state: clients, users, grants, consents, and
  refresh-token family records (see [0007](./0007-refresh-token-rotation.md)).

## Consequences

**Positive:** Codes physically expire and are atomically consumed (`GETDEL`), making
replay structurally hard. Postgres gives ACID guarantees and relational integrity for
the data that needs it. Each store is sized and scaled for its access pattern.

**Negative:** Two datastores to operate, secure, and back up. Redis must be treated as
security-sensitive (encryption in transit, auth, no eviction of unexpired security
keys — use `noeviction` or a dedicated instance). A Redis outage blocks new logins
(acceptable; fail closed).

## Alternatives considered

- **Everything in Postgres:** simpler ops, but high-churn ephemeral writes bloat tables
  and tempt non-atomic "select then delete" code consumption — rejected.
- **Everything in Redis:** loses durability and relational integrity for accounts/grants
  — rejected.
