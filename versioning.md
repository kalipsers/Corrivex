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

### 1.13.0 — Fleet update catalog and cascade updates

**Minor** — adds a fleet-wide software update workflow.

- Full reports now reconcile pending package rows against the installed
  software inventory, so out-of-band installs remove stale update rows when
  the installed version is already current or newer.
- The dashboard adds an **Updates** tab listing all available software updates
  across the fleet, including winget and SMB/local installer sources.
- Clicking a software update opens a cascade modal showing every host with
  that software, installed versions, available versions, and online state.
- Cascade updates queue one host at a time and wait for completion before
  moving to the next host; on failure or timeout, the operator is prompted to
  continue or cancel.

### 1.12.1 — Local installer match visibility fix

**Patch** — fixes discovered SMB installers not appearing for matching apps.

- Installer filename parsing now removes architecture suffix residue such as
  `x86_64`, so `rustdesk-1.4.6-x86_64.msi` maps to `RustDesk` instead of
  `rustdesk 64`.
- Installed software rows now show a `local <version>` chip and **Install**
  button when a newer discovered local installer is available for that app.
- Local-installer matching also ignores common architecture tokens during
  server-side name comparison.

### 1.12.0 — SMB share installer discovery

**Minor** — configured SMB shares can now feed local installer updates.

- Windows agents ask the server for configured SMB share roots during a full
  scan, authenticate with the stored share credential, and scan the share for
  `.msi` / `.exe` installers.
- Discovered installers are analyzed for framework, product name, and version
  using filename metadata plus the existing local-installer detector.
- The server stores discovered installers in the local installer catalog and
  matches newer versions against installed software reported by the same host.
- Matching share installers are shown in the host Updates tab as local
  installer updates and queue the existing `local_install` task type.
- SMB credential matching now respects UNC path boundaries so
  `\\server\share` does not accidentally match `\\server\share2`.

### 1.11.0 — CVE detection precision and coverage

**Minor** — improves CVE scanner coverage while preserving conservative
version-specific filtering.

- NVD scanning now discovers and caches CPE mappings through the free NVD CPE
  API instead of only scanning hard-coded winget IDs.
- NVD CVE lookups paginate through all results and honor version start/end
  inclusive and exclusive bounds.
- OSV queries support structured package identity hints where Corrivex has a
  confident package mapping.
- GitHub Global Security Advisories were added as an optional free source for
  packages that can be mapped precisely.
- FIRST EPSS scores are fetched after CVEs are found and displayed/exported as
  prioritization metadata only.
- New dashboard settings control enabled CVE sources and minimum NVD mapping
  confidence.
- Security view now shows scan coverage diagnostics so unmapped packages,
  skipped versions, and source errors are visible instead of silent misses.

### 1.10.0 — Restart task reconciliation and live output recovery

**Minor** — server and agent now reconcile task state after restarts.

- Agents track active/queued task metadata and keep a bounded live log tail for
  dashboard reconnects.
- Server can request a `task_snapshot` over the existing agent-initiated
  WebSocket connection.
- Agent sends a snapshot after reconnect so stale `delivered` DB tasks are
  marked failed instead of remaining stuck.
- Opening a host in the dashboard asks the connected agent to verify live task
  state and replay recent task log output.
- If the host is offline, the dashboard reports that status cannot be verified
  until the agent reconnects.

### 1.9.0 — Isolated winget package updates + task autohealing

**Minor** — agent-side update execution is now bounded and observable.

- Winget install / upgrade / uninstall operations now run as monitored child
  processes with live stdout/stderr streaming to the dashboard log pane.
- `upgrade_all` no longer calls `winget upgrade --all`. The agent refreshes
  the pending-upgrade list, upgrades one package at a time, reports
  per-package progress, and continues after a package fails or times out.
- New setting `winget_package_timeout_minutes` (default `20`) controls how
  long one winget package process may run before Corrivex kills the process
  tree and moves on.
- Agent task execution is serialized through one worker queue so multiple
  dashboard clicks cannot start overlapping winget mutations on the same host.
  The worker recovers from panics and logs heartbeat lines while a task is
  active.
- Agent WebSocket frames now include `task_progress` events for per-package
  `running`, `completed`, `failed`, and `timeout` updates. The server fans
  these out to the dashboard, which updates package rows and appends progress
  lines without waiting for the final post-task rescan.

### 1.8.0 — Remove chocolatey integration

**Minor** — feature removal. Chocolatey support (1.7.0 / 1.7.3 / 1.7.4,
all local-dev only, never publicly released) was ripped out because in
practice the bootstrap and silent-install flows weren't reliable enough
on the test fleet. Local-file installers (1.7.1) and SMB credentials
(1.7.2) remain — those are the viable long-tail-install paths.

- `internal/choco` package deleted entirely.
- Agent `RunTasks` switch drops the four `choco_*` cases. The agent
  no longer calls `choco.exe` for any task, and the full-scan merge
  no longer reads `choco list` / `choco outdated`.
- `internal/agent/regmerge.go` simplified — removed
  `mergeChocolatey`, `chocoAutoinstallAllowed`, `stripChocoPrefix`.
  `mergeSourceTags` stays because the registry merge still needs it.
- Dashboard Upgrades tab reverts to "Winget" — no more source chips,
  no more "Upgrade all (choco)" split button. Bulk-upgrade uses
  `upgrade_package` for every selection unconditionally.
- `createTask` validator drops the four `choco_*` task types;
  `agent_config` stops returning `choco_autoinstall`.
- DB enum values `choco_install`, `choco_upgrade`,
  `choco_upgrade_all`, `choco_uninstall` are left in the
  `tasks.type` MariaDB ENUM and SQLite CHECK constraint. They're
  harmless orphans — no code path can create them anymore — and
  removing them would force a schema-rebuild for no user-visible
  benefit. The settings row `choco_autoinstall` is also left alone
  (the UI never exposed a toggle and no code reads it).

Go back to 1.7.2 if you want the last state *with* chocolatey —
1.8.0 is the clean "chocolatey never happened" snapshot.

### 1.7.4 — Proactive choco bootstrap + winget source-update fix

**Patch**

Two issues surfaced in a live agent log:

1. `winget source update returned invalid_arguments (non-fatal)`
   The 1.6.3 call passed `--accept-source-agreements
   --disable-interactivity` to the source subcommand. Neither flag
   is accepted by `winget source update` (they belong on
   install/upgrade). The source refresh still happened silently on
   exit 0 but older winget builds returned exit -1978335230
   ("invalid arguments") without doing anything. Stripped the flags;
   the call is now just `winget source update`.

2. **No choco scan on hosts without chocolatey.** 1.7.0 promised
   that the agent would bootstrap chocolatey on hosts that don't
   have it (mirroring EnsureWinget), but I only wired EnsureChoco
   inside the choco_* task handlers — the full-scan merge path
   silently bailed when `choco.IsInstalled()` returned false, which
   is every clean Windows host. Users saw no choco log lines and
   thought the scan was broken.
   Fix: `mergeChocolatey` now runs EnsureChoco proactively on the
   first scan per agent install, gated by the new server setting
   `choco_autoinstall` (default `true`). Air-gapped fleets can set
   it to `false` to keep the agent from reaching
   `community.chocolatey.org/install.ps1`.
   The merge function also logs one line in every branch now —
   "not installed, autoinstall disabled", "running EnsureChoco
   bootstrap", "bootstrap failed: …", or "choco merge: +X new, Y
   confirmed" — so the log stream clearly shows the path taken.

`choco_autoinstall` is exposed through the existing `agent_config`
endpoint; admins who want to flip it can use `set_settings` until a
dedicated UI toggle lands in 1.7.5.

### 1.7.3 — Upgrade tab is source-aware (winget + chocolatey)

**Patch**

The 1.7.0 chocolatey plumbing wired choco packages into the agent
report and created the `choco_*` task types, but the dashboard's
Upgrade tab (historically the "Winget" tab) rendered every pending
upgrade as a winget row. Clicking **Upgrade** on a chocolatey row
sent `upgrade_package` which winget promptly rejected (it doesn't
know about `choco:<id>` identifiers).

- Device-modal "Winget" tab is now labelled **Upgrades** and shows a
  small source chip next to each package name: `winget` (blue),
  `chocolatey` (teal). Rows from both sources appear in a single
  list so admins see the full "what's out of date" picture.
- Per-row Upgrade button dispatches the correct task type:
  - `id` prefix `choco:` → `choco_upgrade`
  - otherwise → `upgrade_package` (winget, unchanged)
- **Upgrade all** now splits into two buttons when both sources have
  pending work:
  - **Upgrade all (winget)** → `upgrade_all` task
  - **Upgrade all (choco)** → `choco_upgrade_all` task
  When only one source has rows, only that button shows.
- Refresh inventory (full_scan) button unchanged — refreshes both
  inventories since the agent's post-task rescan always runs
  winget + choco + registry.

### 1.7.2 — SMB credentials for network-share installer sources

**Minor** — lets agents authenticate against SMB/CIFS file shares
before reading local_install installers from them. Complements 1.7.1:
now admins can point `local_installers.path` at a share even when the
agent's SYSTEM account has no inherent rights on it.

- Schema migration 16: new `smb_credentials` table.
  - `share_root` — the top-level UNC prefix this credential applies
    to, e.g. `\\fileserver\installers`. A longest-prefix match at
    runtime picks the right credential for a given installer path.
  - `username`, `domain` — plain text.
  - `password_enc` — AES-GCM ciphertext (nonce prepended). Base64 in
    the column to stay bytes-safe across MariaDB/SQLite.
  - `notes`, `created_by`, `created_at`.
  - Server-side encryption key: `CORRIVEX_SMB_KEY` env var; when
    unset the server generates a 32-byte key on first boot and
    persists it in a new `smb_key` settings row so restarts don't
    lose decryption capability. The key is never exposed through any
    API — password fields are write-only.
- Admin-gated CRUD:
  - `list_smb_credentials` — returns every row minus the password.
  - `save_smb_credential` — upserts by share_root; accepts password
    plaintext, stores ciphertext, returns row id.
  - `delete_smb_credential` — by id.
- Agent-facing TOFU-auth endpoint `agent_smb_creds` — takes the
  installer path and returns the matching decrypted credential (if
  any) as `{username, domain, password, share_root}`. Password only
  flows to the agent; never returned on the admin list. Requests
  from IPs without an agent token fail.
- Agent hook in `local_install`: before running localinstall.Run,
  if the path starts with `\\`, the agent calls `agent_smb_creds`
  and — when a credential matches — runs
    `net use <share_root> /user:DOMAIN\user PW /persistent:no`
  in a hidden cmd, does the install, then
    `net use <share_root> /delete`
  as a best-effort teardown. Password is redacted from the agent
  log stream; only the share root + username are logged.
- Settings tab grows a "Network shares" card parallel to "Local
  installers": table + add/edit modal with write-only password field
  (placeholder "keep current" when editing an existing row so admins
  don't accidentally blank it out).

Security note: AES-GCM with a per-install key gets password storage
off the "plaintext in DB" level. The weakest remaining link is the
server filesystem — anyone who roots the server host can read the
key and decrypt any stored password. Compromised admins can still
exfiltrate via the agent (the agent legitimately receives the
plaintext). This is the same trust model as Windows credential
manager; documented but not magically fixed.

### 1.7.1 — Local-file installer with framework detection

**Minor** — new admin-curated install path that works for anything
winget and Chocolatey don't cover: MSIs and EXEs staged on a local
disk path or UNC share. Agent reads the file header, identifies the
installer framework (InnoSetup / NSIS / MSI / Squirrel / WiX Burn /
InstallShield / Advanced Installer), and runs the matching silent
flag set. Admins can override per-installer when a vendor used a
non-standard packaging.

- New `internal/localinstall` package:
  - `Detect(path)` → inspects the PE header + string table to
    identify the installer framework. MSI is recognised by extension
    alone. Returns a Framework enum + the canonical silent args.
  - `Run(path, argsOverride, expectedCodes)` → shell-outs with the
    right silent args, waits for completion, returns combined output
    + exit code.
- Frameworks covered with built-in silent-arg templates:
  | Framework | Flags |
  |---|---|
  | `msi` | `msiexec /i <path> /qn /norestart` |
  | `inno` | `<path> /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` |
  | `nsis` | `<path> /S` |
  | `wix_burn` | `<path> /quiet /norestart` |
  | `squirrel` | `<path> --silent` |
  | `installshield` | `<path> /s /v"/qn /norestart"` |
  | `advanced_installer` | falls back to MSI flags (MSI is bundled) |
  | `unknown` | refuses to run unless admin overrode the args |
- Schema migration 15:
  - New `local_installers` table: id, name, path (UNC or local),
    framework_hint (optional), silent_args_override (optional),
    expected_exit_codes (comma-separated ints; defaults to "0,3010"),
    notes, created_at, created_by.
  - `tasks.type` enum extended with `local_install`. SQLite
    table-rebuild same pattern as 13 and 14.
- New admin-gated API: CRUD under
  `/api/?action=list_local_installers`,
  `/api/?action=add_local_installer`,
  `/api/?action=delete_local_installer`.
- New task type `local_install` — payload field `package_id`
  carries the `local_installers.id` as a string. Agent loads the
  row via an existing `agent_config` variant call (not exposed in
  a separate endpoint to keep the agent surface minimal), runs
  `localinstall.Run`, reports exit code.
- Settings → Local installers UI card with add / edit / delete, and
  a device-modal action "Install local…" that enumerates the catalog
  and queues the task.
- Path-whitelist enforcement: path must start with a UNC share
  (`\\server\share\...`) or one of the configured allowed prefixes
  in the `local_installer_allowed_prefixes` setting (default empty,
  so UNC-only until configured). No `C:\Windows\*`, no `%TEMP%\*`.

No SMB authentication yet — 1.7.2 adds that. A 1.7.1 agent can
already reach a UNC share if it already has an authenticated
Windows session or if the share allows anonymous reads.

### 1.7.0 — Chocolatey as a second package manager

**Minor** — adds a full second package manager alongside winget, with
no schema-breaking changes. Migration 14 extends the tasks.type enum
only.

The Chocolatey community repository has roughly 10× the package
coverage of winget for Windows desktop software, with silent-install
logic curated by each package's maintainer. Corrivex now uses choco
wherever winget doesn't have a package.

- New `internal/choco` package shelling out to `choco.exe`:
  - `ListInstalled()` parses `choco list --local-only -r`
  - `ListUpgrades()` parses `choco outdated -r`
  - `RunInstall(id, version)`, `RunUpgrade(id)`, `RunUpgradeAll()`,
    `RunUninstall(id)` wrap `choco install/upgrade/uninstall -y`
    with `--no-progress` for cleaner log output.
  - `EnsureChoco()` bootstraps Chocolatey on hosts that don't have
    it via the official PowerShell install script (matching our
    `EnsureWinget()` pattern). Runs once per agent install and again
    if choco.exe goes missing.
- Agent full scan now merges three inventories: winget →
  chocolatey → registry. Package IDs from choco are namespaced
  `choco:<id>` so they never collide with winget IDs. A package
  found in multiple managers gets `source=winget+choco`,
  `source=choco+registry`, etc.
- Migration 14 — tasks.type enum extended with
  `choco_install`, `choco_upgrade`, `choco_upgrade_all`,
  `choco_uninstall`. SQLite rebuild via the 1.6.3 table-rename
  pattern (CHECK constraints aren't alterable).
- Agent's RunTasks switch adds the four choco cases. All four are
  mutators → post-task rescan runs the now-standard
  `winget source update` + fresh fullScanWS cycle (and the agent
  will also `choco upgrade` refresh where relevant).

Package ID schema reminder:
  `winget`   — canonical winget ID (`Mozilla.Firefox`)
  `choco:`   — prefixed chocolatey ID (`choco:firefox`)
  `reg:`     — prefixed registry subkey name

No dashboard-level UI breakage — the Winget tab still renders only
winget-sourced rows (filtered by `source` containing "winget"),
Installed Software tab shows all three. A full rework of the
upgrade UI to expose chocolatey-initiated upgrades arrives in
**1.7.3** once the base layer is shaken out.

What's coming:
- **1.7.1** — local-file installer with framework detection
  (InnoSetup / NSIS / MSI / Squirrel / WiX Burn / InstallShield).
- **1.7.2** — SMB credentials for network-share installer sources.

### 1.6.3 — Clear already-updated winget rows

**Patch** — fixes two causes of stale rows in the Winget tab.

1. **Agent-side:** after an upgrade/install/uninstall task mutates the
   package set, the agent now runs `winget source update` before
   re-running `winget list --upgrade-available` in the post-task
   `fullScanWS`. Without the source refresh, winget's local index can
   still report the just-upgraded version as "pending" for a few
   seconds — the row lingered on the dashboard until the next full
   scan (24 h by default).
2. **Manual refresh:** new `full_scan` task type. The Winget tab grows
   a small **Refresh inventory** button next to "Upgrade all"; clicking
   it enqueues a `full_scan` task that the agent processes by running
   `fullScanWS` directly. Covers the case where an admin upgraded a
   package outside Corrivex (local cmd, vendor installer) and wants
   the dashboard reconciled without waiting 24 hours.

No schema change. Existing tasks table already accepts the new type
via the `upgrade_all | upgrade_package | install_package | uninstall_package |
check | uninstall_self | windows_update_all | windows_update_single`
ENUM — we extend that ENUM in a new migration #13 to include
`full_scan`.

### 1.6.2 — Agent consumes registry filters + cascade_state derivation

**Patch** — closes two loops the 1.6.0 and 1.6.1 slices left half-wired.

- **Filter settings actually apply.** New agent-facing endpoint
  `GET /api/?action=agent_config` (TOFU token-authenticated) returns
  the subset of server settings the agent needs: every
  `reg_scan_*` key plus sensible defaults for anything unset. Agent
  calls it at the start of every full scan and passes the result to
  `regscan.FiltersFromSettings`. If the fetch fails, agent falls back
  to `DefaultFilters` — same behaviour as 1.6.0.
- **Cascade state populated.** During `SyncInstalledSoftware`, the
  server now sets `installed_software.cascade_state` per row by
  joining against `vendor_versions`:
  - `winget` when `source in (winget, both)` and the vendor cache
    has no matching package_key, or the installed version matches
    the cached latest.
  - `vendor_only` when the vendor cache has a matching key AND the
    installed version is older than the cached latest.
  - `unmanaged` when `source = registry` and no vendor cache
    match — winget doesn't know the app and there's no
    known automated update path.
  - `unknown` otherwise.
- Installed-software modal tab renders a coloured chip next to the
  existing source label:
  - `winget` → neutral grey
  - `vendor_only` → amber ("out of date · vendor only")
  - `unmanaged` → red ("unmanaged — manual update needed")
- `GET /api/?action=installed_software` now returns
  `cascade_state` per row.

Next up (deferred to 1.7.0): actual cascade task dispatch — server
picks the level per upgrade job instead of always invoking winget.
That requires agent-side task-type changes (`upgrade_package_L3`,
etc.) and is a minor bump.

### 1.6.1 — Update cascade: vendor version APIs + Unmanaged state

**Minor** — adds new schema (migration 12), new task types, and a new
agent code path. No breaking protocol changes.

Until 1.6.0 the only upgrade path was `winget upgrade --id X`. If
winget didn't know the package (classic MSI installer, vendor
installer, not in the community source), the task failed and that was
the end. 1.6.1 layers a cascade on top of winget so the server can
still tell the admin what version is current upstream even when
winget can't help.

- **Level 1 — winget** (unchanged). Still tried first for every
  software-upgrade task.
- **Level 2 — vendor JSON API.** New `internal/vendorapi` package with
  one checker per supported vendor. Ships with JSON-only feeds (skips
  HTML scrapers since they rot on every vendor redesign):
  - Google Chrome — `versionhistory.googleapis.com`
  - Mozilla Firefox / Firefox ESR — `product-details.mozilla.org`
  - Node.js — `nodejs.org/dist/index.json`
  - VS Code — GitHub Releases
  - Git for Windows — GitHub Releases
  - Notepad++ — GitHub Releases
  Results cached in a new `vendor_versions` table (migration 12).
  Refreshed on a 6-hour cycle (configurable via
  `vendor_version_interval_hours` setting).
- **Level 3 — explicit `--source winget` retry.** Only engages when
  Level 1 failed with a "not found in any source" style error; some
  packages register under different IDs in `msstore` vs `winget`.
- **Level 5 — Unmanaged.** When every automatic level fails but
  Level 2 knows the upstream version, the server marks the package
  **Unmanaged** with `installed=X, latest_known=Y` in the UI. Admins
  see a clear "winget can't, auto-update isn't possible, go deal with
  it manually" signal instead of a fail-and-retry loop.
- **Schema migration 12:**
  - `vendor_versions` (`package_key` PK, `latest_version`, `channel`,
    `source`, `updated_at`) — shared across the fleet, keyed on the
    canonical vendor-product identifier.
  - `installed_software` gains a `cascade_state` enum
    (`winget` | `vendor_only` | `unmanaged` | `unknown`, default
    `unknown`).
- Dashboard **Installed software** row shows a new chip:
  `vendor v143.0.7727` when Level 2 has a latest version and the host
  is behind, `unmanaged` when Level 5 has tripped. Clicking either
  chip opens a details popover with the source URL and checked-at
  time.
- New env var `VENDOR_VERSION_ENABLED` (default `true`) — turns the
  Level 2 pollers off for air-gapped deployments.

### 1.6.0 — Registry software inventory + configurable skip filters

**Minor** — agent now sees installers that winget doesn't. No schema
change, no manual steps.

Until 1.5.x the agent only ran `winget list`, which misses everything
that was installed through a classic MSI / EXE bundler and never
registered with the Microsoft Store. Those apps simply did not appear
in the inventory at all.

- New `internal/regscan` package reads the Windows uninstall trees
  (HKLM + HKLM Wow6432Node + HKCU) and returns the per-host install list.
- Filters strip the usual garbage: SystemComponent=1 entries,
  Update/Hotfix ReleaseType values, KB-numbered rollups, Microsoft
  redistributables, GUID-only DisplayNames, DisplayNames shorter than
  `min_name_length`, plus admin-supplied regex patterns and publisher
  exact matches.
- Settings live in the `settings` table as `reg_scan_*` keys and can
  be edited from the new **Settings → Registry scan filters** card.
  Agent refetches them at the start of every full scan.
- Merge strategy: winget is authoritative for known IDs; registry
  entries that match a winget row (by DisplayName) flip that row's
  `source` column to `both`; unmatched registry entries appear as new
  rows with `source=registry` and a `reg:` prefix on their package_id.

Expected impact: a typical Windows 11 workstation goes from ~20 winget
rows to 60–120 total inventory entries.

### 1.5.5 — go mod tidy to unblock CI

**Patch**

1.5.4 left `github.com/johnfercher/maroto/v2` and `golang.org/x/image`
marked `// indirect` in `go.mod`, but they are directly imported from
`internal/report/pdf.go`. The CI "vet + test" step runs
`go mod tidy && git diff --exit-code` and flagged the mismatch, failing
the main-branch build right after the v1.5.4 tag was pushed.

- Ran `go mod tidy` locally. Requires now list `maroto/v2` and
  `x/image` at the top, without the `// indirect` marker. `go.sum`
  adjusted to keep the compatibility block tidy (adds `stretchr/objx`,
  `yaml.v3`, `check.v1` that maroto's test tree transitively pulls).
- `go` directive moved to `1.26.1` (what `tidy` settled on after the
  maroto upgrade). Go's auto-toolchain handles it for the
  `setup-go@v5 go-version: 1.23` CI runner.
- No runtime behaviour change — strictly a manifest cleanup.

### 1.5.4 — UTF-8 fonts in PDFs (fix mojibake in reports)

**Patch**

Live 1.5.3 PDF output rendered `·` as `Â·` and `—` as `â€"` —
classic UTF-8-bytes-interpreted-as-Latin-1 mojibake. Root cause:
Maroto's default built-in Helvetica is a 14-core PDF font with a
Latin-1 codepage. Anything outside Win-1252 (em-dash, ellipsis,
middle-dot, and crucially — diacritics in usernames) double-encoded.

- Embedded Go's own TrueType font bundle
  (`golang.org/x/image/font/gofont/{goregular,gobold,gomono,gomonobold}`)
  as custom Maroto fonts. Two families registered: `Go` (proportional,
  normal + bold) replaces Helvetica, `GoMono` (monospaced, normal +
  bold) replaces Courier.
- These are full TTF files with Unicode cmap coverage across Latin,
  Cyrillic, Greek and common symbols, so Slovak/Czech/Polish
  usernames (á, č, ř, ž, ł, ó, ä, ö, ü…) render correctly without
  any per-string preprocessing.
- Template strings cleaned up as well — `·` → `|`, `—` → `-`,
  `…` → `...` in footer pattern + placeholder cells. Defence in depth
  so the layout still looks sane if a custom font ever fails to load.
- File size impact: embedding 4 fonts adds ~900 kB to the binary but
  only adds ~60 kB per PDF (fonts are referenced once, subset embedded
  into the PDF). The fleet ZIP for a 100-host inventory still fits
  well under 10 MB.

### 1.5.3 — Fix PDF table overflow (landscape + truncate + widths)

**Patch**

The 1.5.2 PDF layout overflowed in portrait A4: long winget IDs
(`Microsoft.SQLServer.OLEDBDriver.Backwards…`) and product names
(`Microsoft ODBC Driver 17 for SQL Server`) bled into adjacent columns,
so Host / Name / Version ran together. Maroto's text component renders
unwrapped — unlike HTML it has no `word-break: anywhere` — so columns
that were sized by proportion simply couldn't breathe.

- `installed_software` and `cve_findings` PDFs now render in
  **landscape A4** (297 mm wide). 12-grid column sizes rebalanced from
  real inventory rows.
- All overflow-prone strings (package IDs, names, versions, account
  names, CVE summaries) are truncated with `…` at render-time. Limits
  scale with column width and font size so the result fits even on
  the longest entries.
- Data rows gained `BreakLineStrategy: breakline.DashStrategy` so
  narrow cells that still exceed their width break cleanly rather
  than clipping.
- `local_admins` remains portrait — its columns are already short
  enough to fit in 210 mm.
- Row height raised from 4 mm → 5 mm to give truncated text a little
  breathing room and match the cover's visual rhythm.

### 1.5.2 — Pure-Go PDF export + per-host ZIP batch (Reports slice 3)

**Patch** — adds real server-generated PDFs without a headless browser
or extra container. New dependency: `github.com/johnfercher/maroto/v2`
(pure Go, no CGo).

- Two new `format` values on `GET /api/?action=report`:
  - `format=pdf` — one PDF for the selected scope (fleet or
    `host=HOST`).
  - `format=pdfzip` — only meaningful for `scope=all`: server
    partitions the rows by host, renders one PDF per host, and streams
    the bundle as a zip with a `README.txt` cover and a
    `manifest.json` (host → filename → row count). Hosts with no rows
    are still included with a one-line "no findings" PDF so the fleet
    report is complete.
- New `internal/report/pdf.go` reproduces the Swiss-modernist HTML
  layout in Maroto primitives: brand strip, title, meta column,
  summary KV band, data table with alternating-row background and
  soft grey rules. Helvetica-family (built-in PDF fonts, no font
  embedding) keeps the file small — typical installed-software PDF
  for one host fits in 10–30 kB.
- Reports tab: **PDF** button replaces "Print / PDF" (browser-print
  variant kept as `Open HTML` → user can still Ctrl-P if they prefer
  the web stylesheet). A fourth button, **ZIP (per-host PDFs)**,
  appears only when scope = Entire fleet.
- Page layout: A4, 18 mm top/bottom + 14 mm side margins, page number
  "Corrivex · page n / N" in the bottom-right footer, report title in
  the bottom-left.

### 1.5.1 — Printable HTML reports + PDF via browser (Reports slice 2)

**Patch** — adds a third output format to the report endpoints. No new
server-side dependencies.

- `format=html` on `GET /api/?action=report` returns a standalone,
  self-contained HTML document — Lexend (headings) + Source Sans 3
  (body), embedded Trust-&-Authority palette, Swiss-modernist grid,
  WCAG AAA contrast. Works offline (no CDN beyond the fonts, with a
  system-UI fallback if fonts.googleapis.com is blocked).
- Every HTML report carries a tuned `@media print` stylesheet plus
  `@page { size: A4; margin: 18mm 14mm }`:
  - Print button, scope selector and other UI chrome hide.
  - Table `<thead>` repeats on every printed page.
  - Summary band collapses to a single row for compactness.
  - All colour chips render as outlined text so severity/KEV indicators
    stay legible in black-and-white print.
  - Page footer (`@page @bottom-right`) shows `Corrivex · page <n>`.
- "White mode" is enforced — the stylesheet ignores OS dark-mode
  preferences so reports sent to print look identical on any browser.
- Reports tab grows two new buttons per report card: **Open HTML**
  (new tab) and **Print / PDF** (opens in a print-ready window and
  triggers the browser print dialog immediately — the user then picks
  "Save as PDF" as the destination).
- Internal refactor: `internal/report` now exports `HTML(kind, rows,
  scope, user) (*Output, error)`. Shared base template with partials
  for cover header, summary band, data table.

Browser print-to-PDF is sufficient for all three deliveries (download,
email attachment in a future slice, webhook payload). A server-side
renderer via `chromedp` can replace this in 1.5.3 if scheduled email
delivery needs it.

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
