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

### 1.5.0 — Reports tab + CSV/JSON export (Reports feature family, slice 1)

**Minor** — starts a series of report-family slices (1.5.x). No schema
change; all existing data is re-used through a new `internal/report`
package and a new top-level **Reports** tab in the dashboard.

- `internal/report` encodes three data sources to CSV or JSON:
  - **Installed software** — fleet-wide or single-host snapshot from
    `installed_software`.
  - **Local administrators** — extracted per host from `pcs.local_admins`
    (already populated by every full scan).
  - **CVE findings** — joins `installed_software` × `cve_cache` × `cve_kev`
    just like the Security modal, but in a flat export-friendly shape.
- Three new session-gated API endpoints (`GET /api/?action=report&type=…&format=…`):
  - `type=installed_software|local_admins|cve_findings`
  - `format=csv|json`
  - `scope=all` (fleet-wide) or `host=HOST` (single host)
  - CSV comes as `text/csv; charset=utf-8` with a BOM so Excel picks up
    UTF-8 correctly. JSON is pretty-printed.
- New **Reports** dashboard tab — four summary cards (devices, installed
  packages, distinct local admins, open CVEs) + per-report download
  buttons with a scope selector. Admin-gated.

What's **not** in this slice (coming next):
- Registry inventory + skip filters — 1.5.1
- PDF export (johnfercher/maroto) — 1.5.2
- Scheduling + SMTP + webhook delivery — 1.5.3
- Level-2 vendor version APIs (cascade) — 1.5.4
- Unexpected-admin alerting + SLA tracking — 1.5.5
- Chart panels — 1.5.6

### 1.4.4 — Correct curated winget→CPE mappings

**Patch**

Live testing exposed several entries in `internal/cve/mapper.go` that
pointed at the wrong NVD vendor/product pair, silently hiding real
findings:

- `Oracle.JavaRuntimeEnvironment` → `oracle:jdk` was wrong; NVD tracks
  the JRE under `oracle:jre` (451 entries, most of Java 8's CVE
  backlog). Mapping corrected.
- `WinSCP.WinSCP` → `martin_prikryl:winscp` was wrong; NVD uses
  `winscp:winscp`.
- `Nextcloud.NextcloudDesktop` was missing; added as `nextcloud:desktop`.
- `Oracle.JDK.*` stays mapped to `oracle:jdk` (correct for the JDK
  proper).
- Version-quality guard: packages whose version string has no digits
  (winget occasionally returns `>` or `null`) are skipped by the
  scanner — they can't be meaningfully range-matched and would only
  pollute the cache with "no findings" rows.

Background: NVD's CPE vendor/product strings are idiosyncratic (Mozilla
is `mozilla`, but Notepad++ is `notepad++`; Oracle's JRE is separate
from its JDK). Admins can override any entry via the **Settings → CVE
mappings** textarea without a rebuild.

### 1.4.3 — Fix invisible stat counters under prefers-reduced-motion

**Patch**

The top-bar stat counters (Managed devices / Pending updates / Up to date /
Never seen) were invisible for users with OS-level "reduce motion" enabled.
Root cause: `.stat-value` set `opacity: 0` statically and relied on the
`statReveal` keyframe to fade them in, but the global
`@media (prefers-reduced-motion: reduce)` rule disables all animations —
so the element stayed at `opacity: 0`. Moved the initial state into the
keyframe's `from` step with `animation-fill-mode: both`, so when animations
are disabled the element falls back to its default visible state.

### 1.4.2 — Drop distro-wrapped OSV entries + version-range filter

**Patch**

Shipping the feature to a live host surfaced two classes of false
positives from OSV:

- **Distro-wrapped IDs** — `UBUNTU-CVE-*`, `DEBIAN-CVE-*`, `RHSA-*`,
  `ALAS-*`, `SUSE-SU-*`, `USN-*`, `DSA-*` etc. These are Linux
  distribution tracker entries that reuse a product name but describe
  distro-packaged versions with distro-specific version strings
  (`0.74-1ubuntu1`), often with no `fixed` event at all. They're
  irrelevant to a winget/Windows-native install. `internal/cve/osv.go`
  now drops them up front — the canonical `CVE-YYYY-NNNN` entry, if the
  vulnerability is real, is separately indexed and still picked up.
- **Unfiltered server-side matching** — OSV's `/v1/query` endpoint only
  version-filters reliably when the request specifies an ecosystem
  whose versioning scheme OSV understands. Corrivex passes winget IDs
  with no ecosystem, so OSV was returning every PuTTY CVE ever
  published — including 2020-era entries fixed in 0.74 — against a host
  running 0.83. We now post-filter results against each entry's
  `affected[].ranges[].events[]`: a CVE is only kept if the installed
  version falls inside an `introduced…fixed` span (or
  `introduced…last_affected`). The range matcher uses the existing
  dotted-numeric `compareVer` with a string-compare fallback.
- Entries with no usable range information (no `events` at all on any
  range) are kept conservatively — better a rare false positive than
  missing a genuinely-unbounded CVE.

### 1.4.1 — Security moved to its own modal + linkable CVE IDs

**Patch**

- The Security view is no longer squeezed into the device-modal tab
  strip. A new **Security** button in the device-modal footer opens a
  dedicated wider modal (~1200 px, 90 vw on large screens), so the CVE
  table can breathe — summary text isn't clipped, severity + CVSS fit
  on one line, and the filter input lives at the top. Closes cleanly
  with Esc or backdrop click.
- CVE IDs are now always clickable, including the ecosystem-prefixed
  variants you see from OSV:
  - `CVE-YYYY-NNNN` → nvd.nist.gov
  - `UBUNTU-CVE-*`, `DEBIAN-CVE-*`, `RHSA-*` → nvd.nist.gov (prefix stripped
    to the canonical CVE-YYYY-NNNN)
  - `GHSA-*` → github.com/advisories
  - `ALAS-*`, `SUSE-SU-*` etc → respective vendor pages where known
- The winget upgrade rows continue to show the inline `N CVEs` chip
  (unchanged from 1.4.0).

### 1.4.0 — CVE scanning for installed software + available updates

**Minor** — significant new capability with a fully migrated schema
(automatic — no manual steps). Adds an outbound dependency on public CVE
feeds (OSV, NVD, CISA KEV); see `CVE_SCAN_ENABLED` if you need to disable
it on air-gapped deployments.

- Server now runs a background CVE scanner that, for every unique
  `(package_id, version)` pair across all hosts' `installed_software`
  snapshots, queries OSV first and falls back to NVD (by CPE) on miss.
  Results are cached per `(pkg_id, version)` — 100 hosts running the
  same Firefox build = one API query. Cache TTL is 24 h; the scanner
  wakes on startup + every 6 h + on-demand.
- CISA KEV (Known Exploited Vulnerabilities) catalog is synced daily.
  Any CVE in that list gets a **KEV** chip in the UI, flagging that it's
  being actively exploited in the wild.
- New **Security** sub-tab in the device modal — lists every CVE
  affecting the host's installed software, grouped by package, with
  severity + CVSS + KEV chip + "fixed in" version. Empty state is a
  friendly "No known CVEs" instead of a blank table.
- **Winget upgrade tab** — each available-upgrade row now shows a red
  chip `fixes N CVEs (K critical)` when the current installed version
  has findings that the target version resolves. Diff is computed
  server-side from the cache, so the chip renders instantly without
  per-row API calls.
- **Dashboard top bar** — new CVE counter next to the schema version:
  `CVEs: N open / K KEV`. Links to a new all-hosts roll-up view
  (filterable by severity / KEV / host).
- New API endpoints (admin/operator session required):
  - `GET /api/?action=cve_findings&host=HOST` — per-host CVE list
  - `GET /api/?action=cve_summary` — dashboard counters
  - `POST /api/?action=rescan_cves` — admin-only, forces a full
    rescan ignoring the 24 h cache
- Schema migration **11** — `cve_cache` (keyed on `pkg_id+version`),
  `cve_kev` (catalog snapshot). Idempotent, runs on startup.
- Winget-ID → CPE mapping lives in `internal/cve/mapper.go` as a
  hand-curated Go map covering the ~80 most common winget IDs. Unmapped
  packages fall back to a fuzzy `vendor:product` guess parsed from the
  winget ID. Admins can extend the map without a rebuild via the new
  **Settings → CVE mappings** textarea (stored in the `settings` table).
- Two new env vars:
  - `CVE_SCAN_ENABLED` (default `true`) — master switch.
  - `NVD_API_KEY` (optional) — raises the NVD rate limit from 5→50
    requests per 30 s. Sign up free at nvd.nist.gov/developers.

### 1.3.2 — Auto-mitigate package_agreements_not_accepted

**Patch**

Winget occasionally refuses to install/upgrade with
`0x8A150111 PACKAGE_AGREEMENTS_NOT_ACCEPTED` even when we already pass
`--accept-package-agreements` — usually because a source agreement went
stale or a non-TTY context tripped the prompt code path. Three layered
mitigations now paper over it:

- **`--disable-interactivity`** added to every winget install / upgrade /
  uninstall / source-update invocation so winget never blocks waiting on
  a prompt that can't happen anyway.
- **`SourceUpdate()`** helper (`winget source update --accept-source-
  agreements`) exposed to the agent.
- **Retry-once on `0x8A150111`**: on the first failure with that exit
  code, the agent runs `SourceUpdate()` and retries the operation exactly
  once. A log line is streamed to the dashboard so you can see the
  fallback happened.

No protocol or schema changes — existing agents pick this up at their
next self-update.

### 1.3.1 — Decodeable winget exit codes + timezone

**Patch**

- Task results for winget installs/upgrades used to appear as gibberish
  like `exit:2316632108`. Root cause: Windows surfaces winget's HRESULT
  exit codes as uint32 but Go typed them into `int` without sign-
  extension, so my lookup table (keyed on the Microsoft-documented signed
  form, `-1978335188`) never matched. `runWinget2` and the winupdate
  PowerShell runner now fold the uint32 back through `int32` → `int`,
  so the known-code table hits.
- Expanded the known-code table with the winget errors that were most
  commonly seen but unmapped: `package_already_installed`
  (`0x8A15002C`), `installer_not_applicable` (`0x8A15002E`),
  `update_not_applicable` (`0x8A150033`), `update_all_has_failure`
  (`0x8A150034`), `install_failed` (`0x8A150035`), `dependency_not_found`
  (`0x8A150037`), `download_failed` (`0x8A150008`), `operation_canceled`
  (`0x8A150027`), `package_agreements_not_accepted` (`0x8A150111`), and
  a few others.
- Unknown negative codes now render as `exit:0x8A15XXXX` — same format
  Microsoft's returnCodes doc uses — so admins can paste the hex
  straight into Google / the docs and find the semantic name.
- New `TZ` env var threaded through both compose files and
  `.env.example`. It sets the container timezone on **both** the MariaDB
  and Corrivex-server containers (MariaDB's `time_zone=SYSTEM` follows
  the OS TZ), so `CURRENT_TIMESTAMP` from the DB and Go's `time.Now()`
  no longer disagree. Use an IANA name such as `Europe/Bratislava` or
  `America/New_York`. Defaults to `UTC` when unset — which matches the
  historical behaviour, so existing deployments that don't set `TZ`
  don't shift.

### 1.3.0 — Per-host installed-software inventory + version history

**Minor** — significant new capability with a fully migrated schema
(automatic — no manual steps).

- Each full scan now also runs `winget list` and ships the result as a new
  `installed_software` field in the report. The server diffs that against
  the previous snapshot for the host and writes one of `installed`,
  `updated`, or `removed` rows into a per-package audit log
  (`installed_software_history`). The current snapshot lives in
  `installed_software` (one row per host+package).
- New device-modal sub-tab **Installed software** lists every package
  reported, with a search filter, monospace IDs, version, and source.
  Click any row to expand a chronological version-history table for that
  package — versions, change types, timestamps. Lazy-loaded on first tab
  click.
- New API endpoints (admin session required):
  - `GET /api/?action=installed_software&host=HOST` — current snapshot
  - `GET /api/?action=software_history&host=HOST&pkg_id=ID&limit=N` — audit
- Schema migration **10** — `installed_software` + `installed_software_history`
  tables added to both MariaDB and SQLite migration paths. Idempotent.
- `DeletePC` now also wipes both new tables so a force-removed device
  doesn't leave orphaned inventory rows.
- Windows-only: agent's `winget.ListInstalled()` reuses the same column-
  aware parser as `winget upgrade`. Entries without a winget-style
  `Vendor.Product` ID (Add/Remove Programs leftovers) are skipped — those
  aren't actionable from winget anyway.

### 1.2.2 — Realistic WU sizes + persistent install state

**Patch**

- Windows Update size column was wildly wrong for cumulative updates
  (KB5083769 reported as 92 GB on Win11 24H2). Root cause:
  `IUpdate.MaxDownloadSize` is the bundle's worst-case sum across every
  variant. The agent now prefers `MinDownloadSize` (the size of the variant
  that actually applies to the host — same number Windows Settings shows)
  and only falls back to `MaxDownloadSize` if `Min` is zero.
- Once an update install task completes, the row used to disappear silently
  on the next post-install rescan. Now the dashboard remembers per-modal-
  session which update_ids were just installed and keeps the row visible
  with an **installed** chip — or **reboot pending** when the install
  reported `result_code=3010` — until the modal closes. Works for both
  single-update installs and *Install all*. The remembered set is cleared
  when you close the modal or switch to a different host so it can't bleed
  state between sessions.

### 1.2.1 — Pull-from-Hub deployments + Docker Hub Overview

**Patch** — packaging only, no runtime change.

- `docker-compose.yml` now references the published image
  `kalipserproit/corrivex:latest` (override with `CORRIVEX_IMAGE=...`) and
  uses `pull_policy: always`. No more local `docker compose build` on the
  deployment host — Docker just pulls the released image.
- New `docker-compose.build.yml` for development / air-gapped boxes — same
  project name + same volume, but builds the image locally from `Dockerfile`.
- `deploy/deploy.sh` rewritten around the pull-first flow: it now ships
  only `docker-compose.yml` + `.env.example` to the remote host (instead of
  the full source tree), seeds `.env`, then runs `docker compose pull && up -d`.
  Set `CORRIVEX_IMAGE` to pin a specific version.
- `DOCKERHUB.md` — repo-overview Markdown for the Docker Hub image page,
  containing the quickstart compose snippet, env-var reference, image-tag
  meanings, and the architecture diagram.
- `release.yml` adds a `peter-evans/dockerhub-description` step that
  publishes `DOCKERHUB.md` to the Docker Hub repo's Overview tab on every
  tag. Requires the Docker Hub token to have **Read, Write & Delete** scope.
- README quickstart rewritten to walk through the pull-first flow + the
  build-from-source escape hatch.

### 1.2.0 — Wildcard domain whitelist

**Minor**

- Allowed-domains list now honours a single literal `*` entry as a wildcard:
  any domain (including empty) is permitted to enroll. Useful for closed
  networks where the dashboard is the only access control. Add or remove the
  `*` row from the dashboard's **Allowed domains** tab as you would any other
  entry. Existing per-domain entries continue to work unchanged.
- Dashboard placeholder + hint on the Allowed-domains tab now mentions the
  wildcard so it's discoverable.

**Patch**

- `scripts/bump-version.sh` writes JSON and Markdown as explicit UTF-8 so
  non-ASCII strings (em-dash, ©) round-trip cleanly on Windows-hosted
  toolchains. The script also probes Python interpreters with `--version`
  before using them, skipping the Microsoft Store stub at
  `C:\…\WindowsApps\python.exe`.

### 1.1.1 — CI / Release pipeline

**Patch** — internal infrastructure, no runtime change.

- `.github/workflows/ci.yml` — vet + test + cross-compile sanity build on
  every push and PR to `main`.
- `.github/workflows/release.yml` — on a `vX.Y.Z` tag, builds all binaries
  with the version embedded, packages the Windows release zip, computes
  SHA256 sums, creates a GitHub Release with the matching changelog
  section as the body, and pushes a Docker image to Docker Hub
  (`<DOCKERHUB_USERNAME>/corrivex:X.Y.Z` and `:latest`).
- `scripts/bump-version.sh` — one-shot helper that bumps SemVer in
  lock-step across `internal/version/version.go`, both `versioninfo.json`
  files, and inserts a stub in `versioning.md`. Falls back to `python` if
  `python3` isn't on PATH.
- README — new "CI / Release pipeline" section documenting required
  GitHub repo secrets (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`).

### 1.1.0 — QR code for TOTP setup

**Minor**
- Profile → "Enable 2FA" now shows a scannable QR code alongside the secret
  and the otpauth URL. QR is rendered server-side (pure-Go `rsc.io/qr`) and
  delivered as an inline data URL — no CDN, no external image fetch, works
  offline.

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
