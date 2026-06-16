# 10. Subject identifiers: pairwise PPID per client

**Status:** Accepted

## Context

The `sub` claim identifies the end user. With a **public** subject identifier, the same
`sub` is returned to every client, so two colluding (or breached) relying parties can
correlate that "user X at RP-A" is "user X at RP-B" — a cross-service tracking and
privacy leak the user never consented to. OIDC Core defines a **pairwise** subject type
that returns a different, opaque, stable `sub` to each client (or each sector).

## Decision

The provider issues **pairwise (PPID) subject identifiers by default**: each client (or
`sector_identifier`) receives a distinct, stable, opaque `sub` for a given user, derived
deterministically (e.g. a keyed hash of internal user id + sector). A public `sub` is
available only by explicit, justified client configuration.

## Consequences

**Positive:** Clients cannot correlate users across applications, satisfying privacy and
data-minimisation expectations (and regulatory pressure). The mapping is stable per
client, so each client still gets a durable user key.

**Negative:** The provider must maintain (or deterministically derive) the PPID↔user
mapping and key it securely; the derivation key is sensitive (rotating it would change
every `sub` — so it is long-lived and KMS-guarded, see
[0005](./0005-key-custody.md)). Support/debugging is harder when `sub` differs per client
— mitigated by an internal admin view that resolves PPID→user.

## Alternatives considered

- **Public `sub` for everyone:** simplest, best for debugging, but enables cross-client
  tracking — rejected as the default.
- **Per-request random `sub`:** breaks the "stable identifier" contract clients rely on —
  rejected.
