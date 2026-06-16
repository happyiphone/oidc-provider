-- =====================================================================
-- OIDC Provider — PostgreSQL durable schema
-- Realizes the data model in README + ADR-0006 (durable state only).
-- Ephemeral artifacts (auth codes, PAR requests, sessions, nonce/jti
-- replay caches) live in Redis with TTLs and are NOT modeled here.
--
-- Conventions: UUID PKs (gen_random_uuid via pgcrypto), TIMESTAMPTZ,
-- soft-delete avoided (revocation is explicit state), all FKs ON DELETE
-- guarded. Targets PostgreSQL 14+.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()

-- ---------------------------------------------------------------------
-- CLIENTS  (ADR-0001/0008/0009/0010)
-- ---------------------------------------------------------------------
CREATE TYPE client_type        AS ENUM ('public', 'confidential');
CREATE TYPE token_auth_method  AS ENUM
    ('none', 'client_secret_basic', 'client_secret_post',
     'private_key_jwt', 'tls_client_auth');
CREATE TYPE subject_type       AS ENUM ('pairwise', 'public');

CREATE TABLE clients (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                TEXT NOT NULL UNIQUE,            -- public identifier
    client_type              client_type NOT NULL,
    client_name              TEXT,
    -- ADR-0008: prefer private_key_jwt; secret only for legacy
    token_endpoint_auth_method token_auth_method NOT NULL DEFAULT 'private_key_jwt',
    client_secret_hash       TEXT,                            -- bcrypt/argon2; NULL unless client_secret_*
    jwks_uri                 TEXT,                            -- for private_key_jwt
    jwks                     JSONB,                           -- inline alternative to jwks_uri
    -- ADR-0010: subject identifier strategy
    subject_type             subject_type NOT NULL DEFAULT 'pairwise',
    sector_identifier        TEXT,                            -- groups redirect_uris for pairwise sub
    -- ADR-0009: sender-constraining toggles
    require_par              BOOLEAN NOT NULL DEFAULT TRUE,
    dpop_bound               BOOLEAN NOT NULL DEFAULT FALSE,
    -- registration / lifecycle
    is_active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT secret_requires_secret_method CHECK (
        (token_endpoint_auth_method IN ('client_secret_basic','client_secret_post'))
            = (client_secret_hash IS NOT NULL)
    )
);

-- redirect_uris are EXACT-match (ADR/threat T2,T12). Stored normalized,
-- one row each, so matching is an indexed equality — never LIKE/substring.
CREATE TABLE client_redirect_uris (
    client_id    UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,                               -- absolute, normalized
    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE client_grant_types (
    client_id  UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    grant_type TEXT NOT NULL,   -- authorization_code | refresh_token | client_credentials | device_code
    PRIMARY KEY (client_id, grant_type)
);

CREATE TABLE client_scopes (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope     TEXT NOT NULL,
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE post_logout_redirect_uris (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    uri       TEXT NOT NULL,
    PRIMARY KEY (client_id, uri)
);

-- ---------------------------------------------------------------------
-- USERS
-- ---------------------------------------------------------------------
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT UNIQUE,
    email           CITEXT UNIQUE,                            -- case-insensitive
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash   TEXT,                                     -- argon2id; NULL if federated-only
    -- credential-change → global revocation (threat tree (c)): bump this,
    -- and revoke all token families + sessions whose issued_at < this.
    credentials_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    profile_claims  JSONB NOT NULL DEFAULT '{}'::jsonb,       -- name, given_name, etc.
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- CITEXT needs the extension:
CREATE EXTENSION IF NOT EXISTS citext;

-- MFA / WebAuthn registrations
CREATE TYPE mfa_kind AS ENUM ('totp', 'webauthn', 'recovery_code');
CREATE TABLE user_mfa_methods (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        mfa_kind NOT NULL,
    secret_ref  TEXT NOT NULL,         -- KMS-encrypted secret / WebAuthn credential id
    public_key  BYTEA,                 -- WebAuthn COSE key
    sign_count  BIGINT DEFAULT 0,      -- WebAuthn counter (clone detection)
    label       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_user_mfa_user ON user_mfa_methods(user_id);

-- ---------------------------------------------------------------------
-- PAIRWISE SUBJECT MAP  (ADR-0010)
-- Deterministic derivation is preferred, but a persisted map lets the
-- derivation key rotate without breaking existing PPIDs, and powers the
-- admin PPID->user resolver.
-- ---------------------------------------------------------------------
CREATE TABLE subject_identifiers (
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sector_identifier TEXT NOT NULL,        -- per client sector
    ppid             TEXT NOT NULL,         -- opaque, stable sub for this sector
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, sector_identifier),
    UNIQUE (sector_identifier, ppid)        -- ppid unique within a sector
);

-- ---------------------------------------------------------------------
-- CONSENTS
-- ---------------------------------------------------------------------
CREATE TABLE consents (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes_granted TEXT[] NOT NULL,
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ,                 -- NULL = until revoked
    revoked_at     TIMESTAMPTZ,
    UNIQUE (user_id, client_id)                 -- one active consent record per pair
);
CREATE INDEX idx_consents_user ON consents(user_id);

-- ---------------------------------------------------------------------
-- GRANTS  (the durable authorization a code/refresh chain descends from)
-- ---------------------------------------------------------------------
CREATE TABLE grants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id     UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes        TEXT[] NOT NULL,
    acr           TEXT,                          -- authentication context reached
    amr           TEXT[],                        -- methods (pwd, otp, webauthn...)
    cnf_jkt       TEXT,                          -- DPoP confirmation thumbprint (ADR-0009), NULL if bearer
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX idx_grants_user   ON grants(user_id);
CREATE INDEX idx_grants_client ON grants(client_id);

-- ---------------------------------------------------------------------
-- REFRESH TOKENS  (ADR-0007: rotation + family reuse detection)
-- A "family" is the chain rooted at the first refresh token of a grant.
-- Rotation inserts a new row (status active) and marks the parent 'used'.
-- Presenting a 'used' or 'revoked' token => revoke the WHOLE family.
-- ---------------------------------------------------------------------
CREATE TYPE refresh_status AS ENUM ('active', 'used', 'revoked');

CREATE TABLE refresh_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id      UUID NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    family_id     UUID NOT NULL,                 -- shared across the rotation chain
    parent_id     UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    token_hash    TEXT NOT NULL UNIQUE,          -- SHA-256 of opaque token; raw never stored
    status        refresh_status NOT NULL DEFAULT 'active',
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);
-- Hot path: look up by token_hash (UNIQUE already indexes it).
-- Family revocation: index family_id for a fast UPDATE ... WHERE family_id = $1.
CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_grant  ON refresh_tokens(grant_id);
-- At most one active token per family (rotation invariant). Partial unique:
CREATE UNIQUE INDEX uq_refresh_active_per_family
    ON refresh_tokens(family_id) WHERE status = 'active';

-- ---------------------------------------------------------------------
-- SIGNING KEYS  (ADR-0005: 3-state lifecycle; private material in KMS)
-- Only metadata + PUBLIC JWK live here; the private key never does.
-- ---------------------------------------------------------------------
CREATE TYPE key_status AS ENUM ('next', 'active', 'retired');

CREATE TABLE signing_keys (
    kid          TEXT PRIMARY KEY,                -- JWKS key id
    alg          TEXT NOT NULL DEFAULT 'ES256',
    kms_key_ref  TEXT NOT NULL,                   -- handle to the KMS/HSM private key
    public_jwk   JSONB NOT NULL,                  -- published at /jwks.json
    status       key_status NOT NULL,
    not_before   TIMESTAMPTZ,                     -- when it may start signing
    not_after    TIMESTAMPTZ,                     -- retirement target
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Exactly one active signing key at a time (rotation invariant).
CREATE UNIQUE INDEX uq_signing_one_active
    ON signing_keys((status)) WHERE status = 'active';

-- ---------------------------------------------------------------------
-- AUDIT LOG  (threat T16: tamper-evident, append-only)
-- App writes only; no UPDATE/DELETE grant. Optional hash-chain for
-- tamper evidence (prev_hash links rows).
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user  UUID,                  -- nullable (system events)
    client_id   UUID,
    event_type  TEXT NOT NULL,         -- token.issued, consent.granted, family.revoked, key.rotated...
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   BYTEA,                 -- hash chain over (prev_hash || row payload)
    row_hash    BYTEA
);
CREATE INDEX idx_audit_time   ON audit_log(occurred_at);
CREATE INDEX idx_audit_client ON audit_log(client_id);
CREATE INDEX idx_audit_user   ON audit_log(actor_user);

-- =====================================================================
-- Key operational queries (referenced by the components):
--
-- Family reuse detection (ADR-0007 / AC-T4-1):
--   SELECT status, family_id FROM refresh_tokens WHERE token_hash = $1;
--   -- if status <> 'active': UPDATE refresh_tokens SET status='revoked',
--   --   revoked_at=now() WHERE family_id = $fam;  -> reject (invalid_grant)
--
-- Credential-change global revocation (tree (c) / AC-c-1):
--   UPDATE refresh_tokens SET status='revoked', revoked_at=now()
--     WHERE grant_id IN (SELECT id FROM grants WHERE user_id = $u);
--   UPDATE users SET credentials_changed_at = now() WHERE id = $u;
--
-- Pairwise sub resolution at /authorize (ADR-0010):
--   INSERT ... ON CONFLICT (user_id, sector_identifier) DO NOTHING
--   RETURNING ppid;  -- or deterministic derivation, persisted for rotation
-- =====================================================================
