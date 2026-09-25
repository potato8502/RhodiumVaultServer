# Security model of Rhodium Vault Server

This document says what the server protects against, what it does not, and how the pieces fit. If something here is wrong or incomplete, please report it (see the end).

## What the server can and cannot see

| Data | Server sees it? |
|---|---|
| Master password | **Never** (only used in the browser) |
| Encryption key | **Never** |
| Vault contents (titles, usernames, passwords, notes, URLs) | **Never** - only AES-256-GCM ciphertext |
| Auth key (login secret derived from the master password) | Briefly on login; stored only as a PBKDF2-SHA256 hash with a random salt |
| Salt and Argon2id parameters | Yes (public by design) |
| Size and timing of your saves, your IP address | Yes |

The database file therefore contains no plaintext. This is asserted by an automated test and was checked by inspecting the database bytes after real use.

## Key derivation and encryption

```
masterKey = Argon2id(NFKC(password), salt(16 random bytes), 64 MiB, 3 iterations, 4 lanes)   [hash-wasm, RFC 9106]
authKey   = HKDF-SHA256(masterKey, info = "rhodium-vault/auth/v1")   -> sent to the server, verified against a stored PBKDF2 hash
encKey    = HKDF-SHA256(masterKey, info = "rhodium-vault/enc/v1")    -> non-extractable WebCrypto AES-GCM key, memory only
vault     = AES-256-GCM(encKey, random 96-bit nonce, plaintext = JSON entries,
                        associated data = "RVS|1|memoryKiB|iterations|parallelism|salt")
```

- The ciphertext is bound to its salt and KDF parameters through the associated data, so parameters cannot be swapped underneath it.
- A fresh random nonce is used for every save. Wrong key, tampering with ciphertext/nonce, or mismatching parameters make decryption fail loudly.
- HKDF is one-way: knowing the auth key (or its stored hash) does not reveal the encryption key.
- Browser and server implementations of Argon2id and HKDF are checked against each other with a shared test vector (`tests/contract`).

## Server hardening

- Session cookie: random 256-bit token (stored hashed), `HttpOnly; Secure; SameSite=Strict`, 30 min idle / 12 h absolute lifetime, all sessions revoked on password change.
- CSRF: `SameSite=Strict` **and** a required custom header **and** a same-origin check on every state-changing API call.
- Brute force: per-IP lockout with exponential backoff after 5 failures plus a global failure budget; applies to login, setup token and current-password checks.
- First start: the account can only be created by someone who has the **setup token from the server log**.
- Strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, no inline script or style, no third-party origins), `nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`, HSTS over HTTPS, `no-store` on API responses. The UI loads nothing from any CDN.
- Optimistic concurrency: saves carry the revision they are based on; a stale save is rejected (HTTP 409), never silently merged or overwritten.
- Storage: SQLite with WAL and `synchronous=FULL`; every mutation is one transaction. A rolling history of previous encrypted versions is kept for recovery.
- Container: non-root user, read-only root filesystem, dropped capabilities, no published app port (only the reverse proxy is exposed).
- Dependencies are checked for known vulnerabilities in CI.

## What this design does NOT protect against

1. **A compromised server.** In every web vault, the server delivers the JavaScript that handles your password. An attacker who controls the server (or your reverse proxy / TLS) can serve modified code that steals the master password. The CSP and the vendored, same-origin code limit *other* attackers (XSS, third-party scripts), but not the operator's own host being taken over. Run it on a host you trust and keep it updated; use a native client (like the Windows app) for the most sensitive secrets.
2. **A compromised browser or PC** (malware, keylogger, malicious extensions). The master password and decrypted entries exist in browser memory while unlocked.
3. **Weak master passwords.** Argon2id slows guessing down but cannot save a guessable password. A strength hint is shown; the minimum is 10 characters.
4. **Memory hygiene.** JavaScript cannot guarantee secrets are erased from memory. Keys are non-extractable and dropped on lock, buffers are zeroed on a best-effort basis, nothing more is promised.
5. **Clipboard leaks.** Copied secrets are cleared after 25 seconds on a best-effort basis (browsers give no way to verify what is on the clipboard); clipboard managers may record them.
6. **Denial of service / availability.** A single small server is not highly available. Keep backups.
7. **Metadata.** The server knows when you log in and save and from which IP.
8. **Multi-user threats.** There is exactly one user; that is deliberate.

## Known limitations of this preview

- No independent security review yet. Treat the version as 0.x until at least one outside review of the protocol and code has happened.
- No two-factor authentication for the web login.
- Reverse proxy misconfiguration is on the operator: with `RVS_TRUSTPROXY=true` the app trusts `X-Forwarded-*` from whoever connects to it, so it must only be reachable through your proxy.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository (Security tab -> "Report a vulnerability"). Do not post exploit details in public issues. You will get an answer and a fix or a clear explanation as quickly as one person can manage.
