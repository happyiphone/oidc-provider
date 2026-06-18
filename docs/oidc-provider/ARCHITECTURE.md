# Architecture

A standards-correct OAuth 2.1 / OpenID Connect provider built on **OpenIddict 6.4 / .NET 9**,
owning policy (users, MFA, consent, claims, keys) and delegating protocol mechanics to the
certified core. See the [ADRs](adr/) for the decisions; this is the component + flow view.

## Components & trust boundaries

```mermaid
flowchart TB
  subgraph browser["End-user browser"]
    UA[User agent]
  end
  subgraph rp["Relying parties"]
    RP[Web app / SPA / native]
    DEV[Device / CLI]
    SVC[Service client]
  end
  subgraph op["OIDC Provider (ASP.NET Core)"]
    direction TB
    OING[/"JAR/JARM + DPoP middleware"/]
    AUTHZ["AuthorizeController\nlogin · MFA step-up · consent · code"]
    TOKEN["TokenController\ncode/refresh/client-cred/device/ciba/token-exchange"]
    LOGOUT["Logout · BCL + FCL fan-out"]
    OTHER["UserInfo · PAR · /register · /device · /ciba · /admin/ui · /account/portal"]
    CORE["OpenIddict core\n(validation, token mint, JWKS, discovery)"]
  end
  subgraph data["State"]
    PG[("PostgreSQL\nclients · users · grants · refresh families · audit")]
    REDIS[("Redis\ncodes · PAR · sessions · challenges · DataProtection ring")]
    KMS[["KMS / HSM\nsigning keys (private never in app)"]]
  end

  UA -->|"authorize / login / consent (TLS)"| OING --> AUTHZ
  RP -->|token, userinfo| TOKEN
  DEV -->|device_code| TOKEN
  SVC -->|client_credentials / private_key_jwt / mTLS| TOKEN
  AUTHZ --- CORE
  TOKEN --- CORE
  LOGOUT -->|"logout_token (back-channel)"| RP
  LOGOUT -->|"iframe (front-channel)"| UA
  CORE --> PG
  CORE --> REDIS
  AUTHZ --> REDIS
  CORE -. "sign (never exports key)" .-> KMS
```

Trust boundary: everything in **op** is the authorization server; private signing keys live only in
**KMS**. Browser↔OP and OP↔KMS/DB/Redis are the crossings to defend (TLS, network policy, the
threat model in [`threat-model.md`](threat-model.md)).

## Authorization-code + PKCE flow (the core path)

```mermaid
sequenceDiagram
  participant U as Browser
  participant RP as Relying Party
  participant OP as Provider
  participant K as KMS
  RP->>OP: PAR push (optional) → request_uri
  RP->>U: redirect to /authorize (PKCE S256, state, nonce)
  U->>OP: GET /authorize
  OP->>U: login (password / TOTP / WebAuthn / federated)
  OP->>U: consent (first-party clients skip)
  OP->>U: 302 redirect_uri?code (single-use, ≤60s, bound to client/redirect/sub/challenge)
  RP->>OP: POST /token (code + code_verifier + client auth)
  OP->>K: sign access + id token (ES256)
  OP->>RP: access (JWT, opt. cnf.jkt/x5t#S256) + id_token (auth_time, acr/amr) + refresh
  RP->>OP: GET /userinfo (Bearer/DPoP)
```

## Token & session model
- **Access tokens**: ES256 JWT, short TTL; optionally sender-constrained (DPoP `cnf.jkt` or mTLS
  `cnf.x5t#S256`); audience-restricted via Resource Indicators.
- **Refresh tokens**: opaque, reference-tracked, **rotating**; reuse of a rotated token revokes the
  whole family.
- **Sessions**: Redis, fresh `sid` per login (anti-fixation); `sid` → joined RP set drives logout
  fan-out; `auth_time` carried into the id_token.
- **Keys**: 3-state rotation (`next` published → `active` signs → `retired`) in KMS; JWKS publishes
  public keys only.

## Where to read the code
`app/src/OidcProvider.Api/Program.cs` wires the server; `Controllers/` hold the passthrough policy;
`OidcProvider.Core/Services/` hold the domain (PPID, consent, sessions, MFA, signing). The
design→code map is in [`../../app/README.md`](../../app/README.md).
