# Changelog

All notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); releases are cut by tagging `vX.Y.Z`
(see `.github/workflows/release.yml`).

## [Unreleased]

### Added
- **Flows**: device authorization (RFC 8628), CIBA poll mode, token exchange (RFC 8693).
- **Request/response security**: JAR + JARM (RFC 9101), mTLS-bound tokens (RFC 8705),
  Resource Indicators (RFC 8707), Rich Authorization Requests (RFC 9396).
- **AuthN**: WebAuthn browser registration + passwordless/passkey-as-primary login.
- **Logout**: back-channel (BCL 1.0), front-channel (FCL 1.0), session management
  (check_session_iframe).
- **Lifecycle/UX**: dynamic client management (RFC 7592), self-service account portal,
  browser admin console (clients + users).
- **Ops/seams**: SMTP email sender, Redis-backed DataProtection, `Oidc:Pkce:Required` toggle.
- **Repo**: CI coverage, GHCR image publish, Dependabot, CodeQL (staged), Claude agent
  (staged), release/stale/labeler workflows, architecture + runbook docs.

### Security
- **Open-redirect fix**: post-login/MFA/federation `returnUrl` is now validated as a local URL
  (`Url.IsLocalUrl`) — surfaced by CodeQL; regression-tested.
- Enabled secret scanning + push protection, Dependabot security updates, and CodeQL (public).

### Fixed
- `prompt=login` re-prompt loop; missing `auth_time` in id_token; discovery `plain` PKCE.
- Dockerfile: use the .NET image's built-in non-root `app` user.

### Verified
- 25/25 integration/abuse tests; OIDF Basic-OP plan exercised (25 clean); load-measured.
