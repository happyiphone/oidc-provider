# OIDC Provider — Architecture Design

A design-only architecture package for a standards-correct OpenID Connect Provider.
No runtime code — these are the artifacts you build *from*.

## Standards baseline

Design to these explicitly, in precedence order:

- **OAuth 2.1** — consolidates RFC 6749 + mandatory PKCE; drops implicit & ROPC grants
- **OpenID Connect Core 1.0** + **Discovery 1.0**
- **RFC 7636** PKCE (mandatory for all clients)
- **RFC 9126** PAR · **RFC 9449** DPoP (sender-constrained tokens)
- **RFC 8414** AS metadata · **RFC 7517/7518** JWK/JWS · **RFC 7009** revocation · **RFC 7662** introspection · **RFC 7591** dynamic client registration · **RFC 8628** device flow
- **RFC 9700** OAuth 2.0 Security Best Current Practice

## Documents

| Doc | What it is |
|---|---|
| [`adr/README.md`](./adr/README.md) | 10 Architecture Decision Records — the choices that define the system |
| [`component-token-endpoint.md`](./component-token-endpoint.md) | C4 Component design drilling into the Token endpoint internals |
| [`endpoint-spec.md`](./endpoint-spec.md) | Endpoint-by-endpoint request/validation/error spec |
| [`threat-model.md`](./threat-model.md) | STRIDE threat model + attack trees + controls mapping |
| [`delivery-plan.md`](./delivery-plan.md) | Phased roadmap with conformance-suite acceptance gates |
| [`component-authorize-endpoint.md`](./component-authorize-endpoint.md) | C4 Component design of the `/authorize` + PAR / login / consent internals |
| [`authorize-controller.md`](./authorize-controller.md) | Reference ASP.NET Core `/authorize` controller — login→MFA→consent→code state machine |
| [`openiddict-implementation.md`](./openiddict-implementation.md) | Concrete .NET/OpenIddict wiring — each ADR mapped to the code that enforces it |
| [`schema.sql`](./schema.sql) | PostgreSQL durable schema — clients, users, grants, refresh-token families, keys, audit |
| [`abuse-case-tests.md`](./abuse-case-tests.md) | Negative-test catalog — one+ test per threat-model row, gated per phase |

## Reference implementation

A runnable .NET 8 + OpenIddict scaffold realizing these docs lives in
[`../../app/`](../../app/) — see its [`README.md`](../../app/README.md) for the build/run
steps and the design→code map. (Build-ready scaffold; not yet compiled.)

## Definition of "perfect"

Objective acceptance = **green run of the OpenID Foundation Conformance Suite**
for the targeted profile, plus a green **abuse-case suite** (one negative test per
row of the threat model). Anything else is opinion.

## Recommended stack

C#/.NET wrapping a certified core (**OpenIddict**, free + OpenID-certified; or
**Duende IdentityServer** commercial). Performance is not the constraint — a
provider is I/O- and crypto-bound — so ecosystem maturity and a certified protocol
core win. See [`adr/0003-language-runtime.md`](./adr/0003-language-runtime.md).
