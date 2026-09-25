# Changelog

## 0.1.0 - preview
First public preview.

- Zero-knowledge web vault: Argon2id (WebAssembly) -> HKDF-split auth/encryption keys, AES-256-GCM in the browser with the header bound as associated data.
- Single-user server (ASP.NET Core + SQLite): setup-token protected first run, sessions, rate limiting with exponential lockout, CSRF defence, strict CSP and security headers.
- Optimistic concurrency (HTTP 409 on stale saves), history of previous encrypted versions, atomic password change, encrypted backup and restore.
- Web UI: search, favorites, password age warning, masked password field, generator, auto-lock, history/restore, change master password.
- Licensed under AGPL-3.0.
- Docker (non-root, read-only), Caddy compose example, systemd unit.
- 15 browser-crypto tests, 24 server/integration tests including a cross-language Argon2id/HKDF vector.
