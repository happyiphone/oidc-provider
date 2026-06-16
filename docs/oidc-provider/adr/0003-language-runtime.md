# 3. Language and runtime: C# / .NET

**Status:** Accepted

## Context

The brief asked whether another language would be "more performant." This frames the
problem wrongly: an OIDC provider is **I/O- and crypto-bound** (database/Redis round
trips, signature generation, TLS), not CPU-bound business logic. Throughput is gated by
the datastore and the KMS, not by the language's raw speed. The decisive factors are
instead: availability of a **certified protocol core**, cryptographic library quality,
operational maturity, and team familiarity.

## Decision

We build on **C# / .NET** (current LTS). It pairs a high-quality async runtime and
first-class crypto (`System.Security.Cryptography`, KMS SDKs) with **OpenIddict**, an
OpenID-certified core (see [0002](./0002-build-vs-buy-core.md)).

## Consequences

**Positive:** Certified core available; mature async I/O; strong typing reduces a class
of bugs; excellent KMS/observability ecosystem. Performance is more than adequate for an
I/O-bound workload.

**Negative:** Heavier runtime than a Go single binary; container images larger than a
Rust/Go equivalent. Neither matters for this workload.

## Alternatives considered

- **Go (ORY Hydra):** smallest/fastest deploy, certified core. Strong pick if you want a
  standalone identity service and a minimal runtime; loses .NET's integrated app stack.
- **Rust:** best raw performance and memory safety, but the ecosystem for *being* a
  provider is immature (crates are strong for being a *client*). Perf gain is irrelevant
  to an I/O-bound provider — rejected as premature optimization.
- **Java/Kotlin (Spring Authorization Server / Keycloak):** most mature overall; choose
  if already a JVM shop. Heavier footprint than .NET for a greenfield .NET-friendly team.
