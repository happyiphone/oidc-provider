# Architecture Decision Records — OIDC Provider

Nygard-format ADRs. Each records one binding decision, its context, and trade-offs.

| ADR | Decision | One-liner |
|---|---|---|
| [0001](./0001-protocol-baseline.md) | Protocol baseline | OAuth 2.1 + OIDC Core — kills implicit/ROPC by construction |
| [0002](./0002-build-vs-buy-core.md) | Build vs. buy | Wrap a certified core; don't reimplement the protocol |
| [0003](./0003-language-runtime.md) | Language / runtime | C#/.NET — perf isn't the constraint, maturity is |
| [0004](./0004-token-format.md) | Token format | JWT (ES256) access tokens + opaque refresh tokens |
| [0005](./0005-key-custody.md) | Key custody | Private signing keys in KMS/HSM only |
| [0006](./0006-storage-split.md) | Storage split | Redis (ephemeral, TTL) + PostgreSQL (durable) |
| [0007](./0007-refresh-token-rotation.md) | Refresh tokens | Rotation + token-family reuse detection |
| [0008](./0008-client-authentication.md) | Client auth | Prefer `private_key_jwt` over shared secrets |
| [0009](./0009-sender-constraining.md) | Sender-constraining | Design for PAR + DPoP from day one |
| [0010](./0010-pairwise-subject-identifiers.md) | Subject identifiers | Pairwise PPID per client for privacy |
| [0011](./0011-pkce-s256-mandatory.md) | PKCE specifics | Mandatory for all clients; S256 only, `plain` rejected |
