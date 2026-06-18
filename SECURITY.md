# Security policy

This is an OpenID Connect / OAuth 2.1 authorization server — security is the product. Please treat
vulnerabilities accordingly.

## Reporting a vulnerability

**Do not open a public issue.** Report privately via a
[GitHub security advisory](https://github.com/happyiphone/oidc-provider/security/advisories/new).
Include affected endpoint/flow, a reproduction, and impact. Expect an initial response within a few
days.

In scope: authentication/authorization bypass, token/code/session flaws, crypto/signing issues,
PKCE/PAR/DPoP/JAR handling, redirect-URI validation, refresh-token rotation/reuse, IDOR/privilege
escalation, injection, secrets exposure.

Out of scope: the deliberately-labelled **dev-only** secrets/keys in seeders and dev config
(`*-dev-only`, the dev PPID/signing keys); rate-limit tuning; findings that require a compromised
host or controlled environment variables.

## Hardening baseline

The design encodes the OAuth 2.0 Security BCP (RFC 9700) and the threats in
[`docs/oidc-provider/threat-model.md`](docs/oidc-provider/threat-model.md): PKCE-S256 mandatory,
exact redirect-URI match, single-use codes, refresh rotation + family revocation, pairwise
subjects, KMS-custodied signing keys, sender-constrained tokens (DPoP/mTLS), and a hash-chained
audit log. Each maps to an abuse-case test run in CI.

## Production checklist

Never run with `Oidc:Signing:Mode=Dev`, a missing `Oidc:PpidKeyBase64`, the `*-dev-only` secrets,
or `Oidc:Pkce:Required=false` outside the OIDC-Basic certification context. See
[`docs/oidc-provider/RUNBOOK.md`](docs/oidc-provider/RUNBOOK.md).
