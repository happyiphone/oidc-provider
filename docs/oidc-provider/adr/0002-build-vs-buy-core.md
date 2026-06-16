# 2. Build vs. buy: wrap a certified protocol core

**Status:** Accepted

## Context

An OIDC provider's protocol surface — PKCE verification, `redirect_uri` matching,
`at_hash`/`c_hash` computation, JWKS handling, nonce/state binding, token endpoint
error semantics — is where security bugs are born. Each subtle deviation from the spec
is a potential CVE. The protocol is also a *solved* problem: several
OpenID-Foundation-certified implementations exist and are continuously audited.

## Decision

We **wrap a certified protocol core** rather than reimplement OAuth/OIDC. For the
chosen .NET runtime (see [0003](./0003-language-runtime.md)) the core is **OpenIddict**
(free, OpenID-certified). Our code owns *policy and integration* — user store, consent
UX, MFA, claims, admin — and delegates *protocol mechanics* to the core.

## Consequences

**Positive:** Protocol correctness inherits third-party certification and security
review. We focus engineering on the parts that are actually our domain. Upgrades to
track new BCP land via library updates.

**Negative:** We are coupled to the core's extensibility model and release cadence; a
needed extension point (e.g. a bespoke grant) may require contributing upstream or
careful wrapping. Library CVEs become our patch responsibility (mitigated by SBOM +
dependency scanning).

## Alternatives considered

- **Duende IdentityServer:** the commercial gold standard for .NET — choose if budget
  allows and you want commercial support; licensing cost is the trade-off.
- **ORY Hydra (Go):** certified, excellent if you accept a separate service and Go.
- **Keycloak / Spring Authorization Server (Java):** mature, but pulls in the JVM
  stack — see [0003](./0003-language-runtime.md).
- **From-scratch implementation:** rejected — highest risk, no inherited certification.
