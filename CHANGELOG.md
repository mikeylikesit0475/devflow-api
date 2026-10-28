# Changelog

## [0.1.0] — 2026-10-27

### Added
- JWT auth skeleton: password hashing, HS256 access tokens (30 min default), and Bearer-protected `GET /me`.
- `DEVFLOW_JWT_SECRET` required at boot; values shorter than 32 bytes fail at import.
- Expanded auth edge-case test coverage; CORS hardened to `allow_credentials=False`.

### Security
- Advisory: v0.1.0 requires `DEVFLOW_JWT_SECRET` (≥32 bytes). Starting without it now refuses to boot (fail-closed). Previously the service would silently sign tokens with a publicly-known default secret — rotate any tokens issued before upgrade.

### Dependencies
- Passwords migrated from salted SHA-256 to bcrypt (cost 12).
