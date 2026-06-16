# OpenIddict Implementation Guide

Concrete .NET wiring that realizes the ADRs on **OpenIddict** (the certified core chosen
in [`adr/0002`](./adr/0002-build-vs-buy-core.md) / [`adr/0003`](./adr/0003-language-runtime.md)).
This maps each architectural decision to the specific OpenIddict surface that enforces it.
Code is illustrative (current OpenIddict API shape) — pin to the version in your SBOM.

> **Division of labour:** OpenIddict owns protocol mechanics (PKCE check, code issuance,
> token format, discovery, JWKS). *You* own policy: user store, consent UX, MFA, claims,
> pairwise `sub`, KMS signing, rotation. The seams below are where your policy plugs in.

## ADR → OpenIddict enforcement map

| ADR | Decision | OpenIddict surface |
|---|---|---|
| 0001 | OAuth 2.1 + OIDC, no implicit/ROPC | `AllowAuthorizationCodeFlow()` + `AllowRefreshTokenFlow()` only; never `AllowImplicitFlow()` |
| 0001/0011 | Mandatory PKCE S256 | `RequireProofKeyForCodeExchange()` |
| 0004 | JWT ES256 access tokens | `UseAspNetCore()`; access-token format = JWT (default); ES256 via signing cert/KMS key |
| 0005 | KMS signing | Custom `OpenIddictSigningCredentials` backed by a KMS `SigningCredentials` / `AsymmetricSecurityKey` |
| 0006 | Redis codes / Postgres durable | EF Core stores for durable entities; custom token store or short token lifetimes for ephemerals |
| 0007 | Refresh rotation + reuse detect | `SetRefreshTokenReuseLeeway()` + rolling tokens; reuse → OpenIddict rejects, you revoke family |
| 0008 | `private_key_jwt` | `AllowClientAssertion` / configure `token_endpoint_auth_methods_supported` |
| 0009 | PAR + DPoP | `RequirePushedAuthorizationRequests()`; DPoP enabled via degrees of `Set...`/handlers |
| 0010 | Pairwise `sub` | Override the `sub` claim in the principal you build (see §3) |

## 1. Server registration (the spine)

```csharp
services.AddOpenIddict()
    .AddCore(o => o.UseEntityFrameworkCore()
                   .UseDbContext<AuthDbContext>())   // ADR-0006: durable entities
    .AddServer(o =>
    {
        // ADR-0001: only the safe grants
        o.AllowAuthorizationCodeFlow()
         .AllowRefreshTokenFlow()
         .AllowClientCredentialsFlow();
        // implicit / ROPC deliberately absent

        // ADR-0001/0011: PKCE mandatory, S256 only
        o.RequireProofKeyForCodeExchange();

        // Endpoints (see endpoint-spec.md)
        o.SetAuthorizationEndpointUris("/authorize")
         .SetTokenEndpointUris("/token")
         .SetUserInfoEndpointUris("/userinfo")
         .SetIntrospectionEndpointUris("/introspect")
         .SetRevocationEndpointUris("/revoke")
         .SetPushedAuthorizationEndpointUris("/par");   // ADR-0009

        // ADR-0009: require PAR + sender-constraining
        o.RequirePushedAuthorizationRequests();

        // ADR-0004 + 0005: JWT access tokens signed by KMS (see §2)
        o.AddSigningCredentials(KmsSigningCredentials.Es256());
        o.AddEncryptionCredentials(/* or DisableAccessTokenEncryption() if pure JWT */);

        // Short access-token lifetime (threat T3) + rolling refresh (ADR-0007)
        o.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));
        o.SetRefreshTokenLifetime(TimeSpan.FromDays(14));
        o.SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(15)); // retry grace, ADR-0007

        o.UseAspNetCore()
         .EnableAuthorizationEndpointPassthrough()   // your UI handles login/consent
         .EnableTokenEndpointPassthrough();
    })
    .AddValidation(o => { o.UseLocalServer(); o.UseAspNetCore(); });
```

The single most important *negative* fact: **`AllowImplicitFlow()` and the password flow
never appear.** That is ADR-0001 enforced by omission.

## 2. ADR-0005 — KMS-backed signing (keys never in memory)

OpenIddict needs a `SigningCredentials`. Instead of loading a private key, wrap a KMS
`AsymmetricAlgorithm`/`SecurityKey` whose `Sign` delegates to the KMS:

```csharp
// Public key material is local (for JWKS); the private operation is remote.
public static class KmsSigningCredentials
{
    public static SigningCredentials Es256()
    {
        var key = new KmsEcdsaSecurityKey(keyId: "active", region: "...") { KeyId = "active" };
        return new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
    }
}
// KmsEcdsaSecurityKey.Sign(bytes) => kmsClient.Sign(keyId, bytes, ECDSA_SHA_256)
// The private key never leaves the KMS; only Verify uses the local public key.
```

Publish `active`, `retired`-unexpired, **and `next`** keys in `/jwks.json` so verifiers
prefetch before rotation ([`adr/0005`](./adr/0005-key-custody.md)). OpenIddict exposes the
configured signing keys at the JWKS endpoint automatically; register all three lifecycle
keys so the `next` key is published ahead of activation.

## 3. ADR-0010 — pairwise `sub` + claims, in the authorize passthrough

Because we use `EnableAuthorizationEndpointPassthrough()`, *we* build the
`ClaimsPrincipal`. This is the seam for pairwise subjects, `acr`/`amr`, and scope→claims:

```csharp
[HttpGet("/authorize"), HttpPost("/authorize")]
public async Task<IActionResult> Authorize()
{
    var request = HttpContext.GetOpenIddictServerRequest();
    // ... resolve authenticated user + consent (see component-authorize-endpoint.md) ...

    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    // ADR-0010: pairwise PPID, not the raw user id
    identity.SetClaim(Claims.Subject, _ppid.For(user.Id, client.SectorIdentifier));
    identity.SetClaim("acr", authResult.Acr);          // e.g. urn:mfa
    identity.SetClaims("amr", authResult.Amr);         // ["pwd","otp"]
    identity.SetScopes(request.GetScopes());
    identity.SetDestinations(GetDestinations);          // which claims go in id_token vs access_token

    return SignIn(new ClaimsPrincipal(identity),
                  OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
```

OpenIddict turns this principal into the code, then (at `/token`) into the ID and access
tokens — computing `at_hash`, binding `nonce`, and signing via your KMS credentials.

## 4. ADR-0007 — refresh rotation + family reuse detection

Rolling refresh tokens are built in; reuse *detection-with-family-revocation* is your
policy. OpenIddict marks a redeemed refresh token as redeemed; if a redeemed token is
presented again it is rejected (`invalid_grant`). Hook that rejection to revoke the
family:

```csharp
// In the token request handler / an OpenIddict event handler:
if (result.IsRejectedAsReused)   // redeemed token replayed → breach signal
{
    await _grants.RevokeFamilyAsync(tokenFamilyId);   // ADR-0007, threat T4 + tree (c)
    return Forbid(/* invalid_grant */);
}
```

Wire credential-change and explicit logout to `RevokeFamilyAsync` as well (kills
persistence tree (c) in the [threat model](./threat-model.md)).

## 5. ADR-0009 — DPoP sender-constraining

Enable DPoP so tokens carry a `cnf.jkt` confirmation and the validation stack requires a
matching proof:

```csharp
// Server: advertise + require DPoP for flagged clients; OpenIddict validates the proof,
// binds jkt into issued tokens, and the validation handler enforces it at resource time.
o.SetDPoPProofLifetime(TimeSpan.FromMinutes(1));   // replay window (threat T3)
// Per-client: require DPoP when client.DpopBound == true
```

Resource servers then receive `Authorization: DPoP <jwt>` + `DPoP: <proof>`; a stolen
bearer is useless without the client's private key.

## 6. ADR-0008 — asymmetric client auth

Advertise and accept `private_key_jwt`; verify the assertion's signature against the
client's registered `jwks`/`jwks_uri`, with strict `aud`/`exp`/`jti`-replay checks
(OpenIddict validates the assertion; you supply the client key material at registration —
see [`endpoint-spec.md`](./endpoint-spec.md) `/register`).

## 7. Validation hardening (threats T9/T10)

On the resource/validation side, **pin the accepted algorithm to ES256** and never let
the token's own `alg` header pick the verification path — OpenIddict's validation handler
verifies against the configured issuer keys only, which structurally blocks `alg:none`
and RS↔HS confusion. Keep the JWKS fetch over pinned HTTPS with a bounded cache (T10).

## What you still must build (not in the box)

- The **login + consent UI** and MFA/WebAuthn (the authorize passthrough above).
- The **KMS signing adapter** and the **3-state key rotation job**.
- The **pairwise PPID** derivation + admin PPID→user resolver.
- The **token-family** schema and `RevokeFamilyAsync`.
- The **abuse-case test suite** — see [`abuse-case-tests.md`](./abuse-case-tests.md).
- CI wiring of the **OIDF conformance suite** — see [`delivery-plan.md`](./delivery-plan.md).
