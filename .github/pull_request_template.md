## What & why

<!-- What does this change and why. Link any issue. -->

## Type
- [ ] Feature
- [ ] Fix
- [ ] Security
- [ ] Docs / chore

## Checklist
- [ ] `dotnet build` clean (0 errors)
- [ ] `dotnet test` green (integration / abuse-case suite)
- [ ] If it touches a protocol flow, added/updated an abuse-case test
- [ ] If it touches security posture, updated [`docs/oidc-provider/threat-model.md`](../docs/oidc-provider/threat-model.md) / relevant ADR
- [ ] No secrets, real keys, or PII committed
- [ ] Discovery metadata matches behaviour (run-or-reason for conformance if relevant)

## Security impact
<!-- Auth/crypto/token/session implications, or "none". -->
