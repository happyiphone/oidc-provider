# 9. Sender-constraining: design for PAR + DPoP from day one

**Status:** Accepted

## Context

Bearer tokens are usable by anyone who holds them — theft equals impersonation. Two
modern mechanisms close gaps: **PAR (RFC 9126)** pushes the authorization request to the
provider over a back channel and returns a `request_uri`, so request parameters
(including `redirect_uri`, scopes, PKCE challenge) are never exposed or tamperable in the
front-channel URL. **DPoP (RFC 9449)** binds access/refresh tokens to a client-held
key via a per-request proof, so a stolen bearer token is useless without the private key.
Retrofitting either after launch means reworking the authorize and token pipelines.

## Decision

We **architect for PAR and DPoP from the start** — the authorize pipeline accepts a
`request_uri` path and the token/userinfo pipeline has a DPoP proof-validation component
(see [component design](../component-token-endpoint.md)) — even though they ship in a
later hardening phase ([delivery plan](../delivery-plan.md), Phase 3). The data model and
endpoints reserve the hooks (`require_par`, `dpop_bound` per client).

## Consequences

**Positive:** No painful re-architecture later; FAPI 2.0 (which mandates PAR + sender-
constrained tokens) becomes reachable. Front-channel request tampering and bearer-token
theft are both addressable with config, not redesign.

**Negative:** Up-front complexity in the request/response pipeline even before the
features are enabled; components must be written to tolerate both constrained and
unconstrained tokens during rollout.

## Alternatives considered

- **Ship plain bearer + maybe add later:** lower initial effort, but retrofitting token
  binding is a known-painful migration — rejected.
- **mTLS-bound tokens instead of DPoP:** valid alternative for back-channel-heavy
  ecosystems; we keep it as an option but default to DPoP for public/browser clients.
