# Versioning

Corrivex follows [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`.

| Component | Bump when… |
|---|---|
| **MAJOR** (`x`) | Breaking change — DB migration that requires manual steps, agent ↔ server protocol change incompatible with older builds, removed/renamed flag or HTTP route, removed event type, etc. |
| **MINOR** (`y`) | New backwards-compatible feature — new tab in the dashboard, new task type, new agent capability, new optional flag. |
| **PATCH** (`z`) | Backwards-compatible fix — bug fix, performance tweak, doc-only change, refactor without behavioural change. |

**Every change bumps the version.** No exceptions — that's how you can read the
log and tell at a glance whether a roll-out is risky (major) or trivial
(patch). When in doubt, prefer a higher bump.

## Where the version lives

A single source of truth is the constant in `internal/version/version.go`.
Build scripts (`Makefile`, `build.ps1`, `build/release.sh`) read it and pass
`-ldflags "-X github.com/markov/corrivex/internal/version.Version=..."` to
both binaries. The same value is embedded into the Windows file properties
of `corrivex-server.exe` and `corrivex-agent.exe` via `goversioninfo`, so it
shows under **Properties → Details → Product version**.

It also surfaces:

- in the **dashboard top bar**, beside the brand mark
- in the agent's **hello frame** to the server, so the server logs the
  client build per host
- in the response to `GET /api/?action=server_version`

## Release procedure

1. Decide the bump (MAJOR / MINOR / PATCH).
2. Update `internal/version/version.go` — the `Version` constant.
3. Update `cmd/server/versioninfo.json` and `cmd/agent/versioninfo.json` —
   the `FixedFileInfo.FileVersion` and `FixedFileInfo.ProductVersion`
   integer fields *and* the `StringFileInfo.FileVersion` /
   `ProductVersion` strings.
4. Add a new entry at the top of the **Changelog** below.
5. Build:
   ```sh
   make release-windows        # Unix / Git-Bash
   # or
   .\build.ps1 -Release        # Windows native
   ```
6. Verify the embedded version:
   ```sh
   ./bin/corrivex-server  --version            # logs version on start
   ./bin/corrivex-server.exe --version
   # On Windows: right-click corrivex-server.exe → Properties → Details
   ```
7. Tag the commit: `git tag v1.2.3 && git push --tags`.

## Changelog

Newest first. Each entry lists user-visible changes grouped by bump type.

### 1.0.0 — initial release

First tagged release. Establishes the baseline:

**Server**
- Linux/Docker (MariaDB) and Windows-native (SQLite) deployments share one
  codebase. Driver chosen via `--db-driver`.
- HTTP dashboard with role-based auth (admin / operator / viewer), bcrypt-12,
  optional per-user TOTP (RFC 6238), session cookies (`cv_session`,
  HttpOnly + SameSite=Strict + Secure-when-TLS).
- Per-host TOFU agent token (`X-Corrivex-Token`).
- Persistent agent WebSocket (`/api/?action=agent_ws`) with per-host hub,
  live `pc / pc_online / log / task / pc_removed / domain` event stream
  on `/api/?action=ws`.
- Optional TLS via `--tls-cert` / `--tls-key`.
- Windows-server install/uninstall/run subcommands (`CorrivexServer`
  service + auto-restart).

**Agent**
- Single binary, registered as `CorrivexAgent` Windows service.
- Persistent WebSocket session, exponential-backoff reconnect, live log
  streaming, server-pushed tasks.
- winget shell-out (list / upgrade-all / upgrade-one / install / uninstall)
  with auto-installation of winget itself if missing.
- Windows Update via `Microsoft.Update.Session` COM (list / install-all /
  install-by-id).
- Self-update on every reconnect via SHA256 comparison + GitHub-release-style
  rotation.
- TOFU token persisted to `C:\ProgramData\Corrivex\config.json`.
- UTF-8-safe PowerShell invocations for non-ASCII locales.

**Dashboard**
- Trust-&-Authority visual style, Plus Jakarta Sans, no emojis.
- Tabbed device modal: Overview / Winget / Windows update.
- Persistent live-output console pinned in modal, pop-up effect on Upgrade.
- Per-package status chips (queued / running / done / failed).
- Force-remove for offline devices; uninstall-and-remove for online ones.
- Online/offline pill per host, OS column with text wrapping, separated
  winget vs WU update counts.

**Build & deploy**
- `Makefile`, `build.ps1`, `build/release.sh` — single source of truth for
  build.
- Docker-only Linux deployment; Windows release zip
  (`dist/corrivex-windows.zip`).
- One-line Windows installer `deploy/install-server.ps1`.
