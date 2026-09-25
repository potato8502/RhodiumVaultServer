# Rhodium Vault Server

A small, self-hosted password vault with a web interface - for your own server, in the spirit of AdGuard Home: one container, one vault, one user.

> **Status: 0.1 preview.** The design follows well-known zero-knowledge principles and is covered by automated tests, but it has **not** been independently reviewed. Read [SECURITY.md](SECURITY.md) before trusting it with anything important. For high-stakes credentials use an established, audited manager (Bitwarden/Vaultwarden, KeePass).

Part of [Rhodium Software](https://rhodium-software.de). There is also a separate, offline Windows app: [Rhodium Vault](https://github.com/potato8502/RhodiumVault) (the two do not sync yet).

## How it works (short version)

- Your master password never leaves your browser. The browser derives two independent keys from it (Argon2id + HKDF): an **auth key** (sent to the server to log in) and an **encryption key** (stays in browser memory only).
- Everything in your vault is encrypted in the browser with AES-256-GCM **before** it is sent. The server stores ciphertext, public KDF parameters and a one-way hash of the auth key - nothing else.
- There is no account system: the first visitor with the **setup token** (printed in the server log) creates the single vault. Then setup is closed.
- No recovery: if you forget your master password, the data cannot be recovered - by anyone, including you as the operator.

## Features

Setup wizard with password-strength hint, unlock/lock, auto-lock after 5 minutes, entries with search / favorites / password-age warning, masked password field with reveal, password generator, change master password, encrypted backup download, restore from backup, previous versions ("History") with restore, and safe concurrent editing (a stale save is refused instead of overwriting).

Not included (yet): multiple users, sharing, browser extension / autofill, TOTP, attachments, sync with the Windows app, mobile app.

## Quick start (Docker + automatic HTTPS)

Browsers only allow the cryptography this app needs on **HTTPS or `localhost`**, so run it behind a reverse proxy. The included compose file uses Caddy.

```bash
git clone https://github.com/potato8502/RhodiumVaultServer.git
cd RhodiumVaultServer
# 1. put your domain into deploy/Caddyfile (replace vault.example.com), point its DNS at this machine, open ports 80 and 443
docker compose up -d --build
# 2. read the one-time setup token
docker compose logs vault | grep -A1 "Setup token"
```

Open `https://your-domain`, enter the token, choose a master password. Do **not** publish port 8080 directly; only the proxy should reach the app.

Just trying it on one machine? No domain needed: `docker compose -f docker-compose.local.yml up -d --build`, then open `http://localhost:8080` (bound to `127.0.0.1` only).

Without Docker (e.g. in a Proxmox LXC): see the comments in [`deploy/rhodium-vault.service`](deploy/rhodium-vault.service).

## Configuration

Environment variables (or the same keys in `appsettings`):

| Variable | Default | Meaning |
|---|---|---|
| `RVS_DATADIR` | `./data` (`/data` in Docker) | Where `vault.db` lives. **Back this up.** |
| `RVS_TRUSTPROXY` | `false` | Set `true` behind a reverse proxy so client IPs (for rate limiting) and `https` are taken from `X-Forwarded-*`. Only enable it if the app is reachable **only** through that proxy. |
| `RVS_ALLOWINSECUREHTTP` | `false` | Testing only. Browsers block WebCrypto on plain HTTP anyway. |
| `RVS_MAXHISTORY` | `20` | How many previous encrypted versions to keep. |
| `RVS_SESSIONIDLEMINUTES` / `RVS_SESSIONABSOLUTEHOURS` | `30` / `12` | Server-side session limits. |
| `ASPNETCORE_URLS` | `http://+:8080` in Docker | Listen address. |

## Backups and recovery

- **Backup** button in the UI downloads an encrypted JSON file (useless without your master password).
- **Restore:** on a fresh server use "Restore from a backup file instead" on the setup screen.
- Also keep a copy of the `vault.db` volume; the server keeps the last versions of your vault in it.
- **Updating:** `git pull && docker compose up -d --build`. The data volume is untouched.

## Development

```bash
dotnet test tests/Server.Tests          # API, sessions, rate limiting, storage, cross-language crypto vector
node --test "tests/web/*.test.mjs"      # browser crypto (needs Node 22+)
dotnet run --project src/Server         # http://localhost:5000 style URL is shown in the console; localhost counts as a secure context
```

The web UI is plain JavaScript with no build step; the only third-party code is the vendored Argon2 WebAssembly build (`src/Web/js/vendor`, MIT, checksum in `VENDORED.txt`).

## License

Copyright (C) 2026 Rhodium Software. Licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). You may use, study, change and share it freely; if you run a modified version as a network service, you must offer its source code to the users of that service.

The vendored Argon2 build in `src/Web/js/vendor` is MIT licensed by its authors (see `hash-wasm.LICENSE.txt`).
