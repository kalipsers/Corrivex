# Corrivex

Centralised winget + Windows Update orchestration for Windows endpoints, with a
real-time dashboard, role-based admin UI, and a single-binary agent.

- One **server** (Linux/Docker or Windows-native) runs the dashboard, the API,
  the agent hub, and the database.
- Many **agents** — one per managed Windows endpoint — connect back to the
  server and execute pushed tasks.

```
     ┌──────────────────────┐
     │  Admin web browser   │
     └──────────┬───────────┘
                │  HTTP/HTTPS + WS
                ▼
   ┌──────────────────────────┐
   │  corrivex-server(.exe)   │   one of these (Linux Docker OR Windows)
   │  ├─ dashboard            │
   │  ├─ /api/  + WebSocket   │
   │  └─ MariaDB or SQLite    │
   └────────────┬─────────────┘
                │  WSS agent_ws (per host, persistent)
   ┌────────────┴───────────────┬─────────────┬──────────── …
   ▼                            ▼             ▼
 PC1                          PC2           SRV1
 corrivex-agent.exe           corrivex-     corrivex-
 (winget + WU + tasks)        agent.exe     agent.exe
```

## Features

- **winget integration**: scan, upgrade-all, upgrade-package,
  install-package, uninstall-package. Auto-installs winget itself on hosts
  where it's missing (re-register AppX, fall back to GitHub release download).
- **Windows Update integration**: scan via `Microsoft.Update.Session` COM,
  install-all or install-by-id with live progress.
- **Self-updating agents**: server publishes the canonical binary hash; each
  agent compares on every reconnect, downloads and rotates if changed.
- **Role-based admin UI**: admin / operator / viewer. Per-user TOTP (RFC 6238)
  with manual secret entry. First-run setup-admin flow.
- **TOFU per-agent token**: each host gets a 256-bit secret on first contact;
  every subsequent request is `subtle.ConstantTimeCompare`-validated.
- **Optional TLS**: `--tls-cert` / `--tls-key` (or env). Default: HTTP.
- **Two storage backends**: MariaDB (recommended for fleets) or SQLite
  (single-file, perfect for Windows-hosted controllers).
- **Optional encoding-correct PowerShell**: every PS invocation forces
  UTF-8 so non-ASCII (Slovak, Czech, German, Polish, …) round-trips cleanly.
- **CVE scanning (1.4.0+)**: background scanner queries OSV + NVD and the
  CISA KEV catalog on a 6-hour cycle. Per-host Security modal lists every
  CVE affecting the installed software; winget upgrade rows show inline
  chips when upgrading would fix a known vuln.
- **Reports (1.5.0+)**: a dedicated dashboard tab exports three data sets
  (**Installed software**, **Local administrators**, **CVE findings**) in
  five formats — CSV, JSON, HTML, PDF, and a per-host ZIP bundle of PDFs
  — at fleet or single-host scope. See the [Reports](#reports) section
  below for the full matrix.

## Repository layout

```
.
├── cmd/
│   ├── server/          # corrivex-server entry point + Windows-service shim
│   └── agent/           # corrivex-agent entry point (Windows only)
├── internal/
│   ├── api/             # HTTP + WS handlers, auth gating, agent hub wiring
│   ├── agent/           # Windows agent runtime (persistent WS session)
│   ├── auth/            # bcrypt, TOTP, session helpers, role checks
│   ├── db/              # MariaDB + SQLite store, migrations, queries
│   ├── events/          # in-process pub/sub fed to dashboard websockets
│   ├── hub/             # per-host agent connection registry
│   ├── cve/             # CVE scanner (OSV + NVD + CISA KEV), winget→CPE map
│   ├── report/          # CSV / JSON / HTML / PDF / ZIP export encoders
│   ├── web/             # dashboard HTML render + login page
│   ├── winget/          # winget shell-out + auto-install
│   └── winupdate/       # Microsoft.Update.Session COM probes
├── deploy/
│   ├── deploy.sh        # rsync + docker compose to a Linux host
│   └── install-server.ps1   # Windows server one-shot installer
├── build/
│   └── release.ps1      # bundles Windows release zip
├── docker-compose.yml   # Linux/MariaDB deployment
├── Dockerfile           # multi-stage build (Linux server + Windows agent)
├── Makefile             # Unix / Git-Bash entry points
├── build.ps1            # PowerShell build script (Windows native)
└── README.md
```

## Quickstart — Linux + Docker + MariaDB

The recommended deployment for fleets. The server runs from the
**published Docker Hub image** (`kalipserproit/corrivex`) — no Go toolchain
or source checkout needed on the host, just Docker + Compose plugin.

```sh
mkdir -p /opt/corrivex && cd /opt/corrivex

# 1. Drop in the two compose-side files from the repo.
curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/kalipsers/Corrivex/main/docker-compose.yml
curl -fsSLo .env.example       https://raw.githubusercontent.com/kalipsers/Corrivex/main/.env.example

# 2. Create .env with random credentials.
PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
ROOT=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
cat > .env <<EOF
DB_NAME=corrivex
DB_USER=corrivex
DB_PASS=$PASS
DB_ROOT_PASS=$ROOT
API_SECRET=
EOF

# 3. Pull and start.
docker compose pull
docker compose up -d
```

Browse `http://your-host:8484/`. First visit redirects to the **Create first
admin** form. Create the admin, then go to **Allowed domains** and add your
AD domain (or enter `*` to permit any). Then **Enroll device** for the
bootstrap one-liner.

To pin a specific Corrivex version, set `CORRIVEX_IMAGE` before `up`:
```sh
CORRIVEX_IMAGE=kalipserproit/corrivex:1.2.0 docker compose up -d
```

To upgrade later:
```sh
docker compose pull && docker compose up -d
```

`deploy/deploy.sh root@HOST` is a wrapper that pushes `docker-compose.yml` +
`.env.example` to a remote box, generates a random `.env` on the first run,
pulls the image, and brings the stack up — all in one command.

### Building from source instead

When iterating on the server code (or running on an air-gapped box that
can't reach Docker Hub), use `docker-compose.build.yml` — same project
name, same volume, but builds the image locally from the current source:

```sh
docker compose -f docker-compose.build.yml up -d --build
```

To switch back to the published image:
```sh
docker compose -f docker-compose.build.yml down
docker compose pull && docker compose up -d
```

## Quickstart — Windows-native + SQLite

For environments that don't run Linux/Docker. The server runs as a real
Windows service; SQLite is the default backend (single file under
`C:\ProgramData\Corrivex\server\corrivex.db`).

1. Build a Windows release on any machine:

   ```sh
   make release-windows           # Unix/Git-Bash
   # or
   pwsh ./build.ps1 -Release      # PowerShell
   ```

   Output: `dist/corrivex-windows.zip` containing `corrivex-server.exe`,
   `corrivex-agent.exe`, and `install-server.ps1`.

2. Copy the zip to the target Windows host and unpack.

3. Open an **Administrator** PowerShell in the unpacked folder and run:

   ```powershell
   .\install-server.ps1 -Listen ':8484'
   # …with HTTPS:
   .\install-server.ps1 -Listen ':8443' -TLSCert 'C:\path\srv.pem' -TLSKey 'C:\path\srv.key'
   ```

   This stages both `.exe` files into `C:\ProgramData\Corrivex\server\`,
   registers the **CorrivexServer** service, sets auto-restart recovery
   actions, and starts it.

4. Browse `http://localhost:8484/`. Same first-admin flow as above.

Service control:
```powershell
sc.exe start CorrivexServer
sc.exe stop  CorrivexServer
corrivex-server.exe status
corrivex-server.exe uninstall
```

## Enrolling a Windows endpoint

Once at least one allow-listed domain is configured, the dashboard's
**Enroll device** tab shows a single-line PowerShell command to run on the
endpoint as Administrator:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex (iwr -UseBasicParsing ('http://YOUR_SERVER:8484/api/?action=bootstrap&host='+$env:COMPUTERNAME+'&domain='+(Get-WmiObject Win32_ComputerSystem).Domain)).Content"
```

It downloads `corrivex-agent.exe` from the server, registers the
**CorrivexAgent** service, preserves any existing TOFU token, and starts.
The agent immediately opens its persistent WebSocket back to the server.

To remove an endpoint: open its detail modal on the dashboard → **Uninstall &
remove** (graceful, the agent self-cleans) or **Force remove** (immediate
DB-side delete for offline hosts).

## Configuration reference

### Server flags / env

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--addr` | `CORRIVEX_ADDR` | `:8484` | Listen address |
| `--db-driver` | `DB_DRIVER` | `mariadb` (linux) / `sqlite` (windows) | Backend choice |
| `--db-path` | `DB_PATH` | `corrivex.db` (linux) / `C:\ProgramData\Corrivex\server\corrivex.db` (windows) | SQLite file path |
| `--db-host` | `DB_HOST` | `127.0.0.1` | MariaDB host |
| `--db-port` | `DB_PORT` | `3306` | |
| `--db-name` | `DB_NAME` | `corrivex` | |
| `--db-user` | `DB_USER` | `corrivex` | |
| `--db-pass` | `DB_PASS` | *(empty)* | |
| `--require-domain` | `REQUIRE_DOMAIN_CHECK` | `true` | Gate enrollment on allow list |
| `--history-keep` | `HISTORY_KEEP` | `50` | Reports per (host, action) to retain |
| `--api-secret` | `API_SECRET` | *(empty)* | Optional shared secret for agent endpoints |
| `--agent-bin` | `AGENT_BIN` | *(see below)* | Path to `corrivex-agent.exe` to serve at `/api/?action=agent.exe` |
| `--tls-cert` | `TLS_CERT` | *(empty)* | Enable HTTPS |
| `--tls-key` | `TLS_KEY` | *(empty)* | |
| `--cve-scan-enabled` | `CVE_SCAN_ENABLED` | `true` | Background CVE scanning against OSV + NVD + CISA KEV |
| `--nvd-api-key` | `NVD_API_KEY` | *(empty)* | Optional NVD API key — lifts rate limit from 5 to 50 requests per 30 s |

`--agent-bin` defaults to `./corrivex-agent.exe` next to the server binary on
Windows; on Linux the Dockerfile sets `AGENT_BIN=/app/corrivex-agent.exe`.

### Windows-server subcommands

```
corrivex-server.exe                  run in the foreground
corrivex-server.exe install   ...    register Windows service
corrivex-server.exe uninstall        remove Windows service
corrivex-server.exe start | stop     control the service
corrivex-server.exe status           query service state
corrivex-server.exe run -- ...       run with explicit flags (skip install)
```

### Agent subcommands

```
corrivex-agent.exe install --server=URL [--check-min=N] [--scan-hrs=N] [--svc-name=NAME]
corrivex-agent.exe uninstall
corrivex-agent.exe start | stop | status
corrivex-agent.exe run             (foreground)
```

## Security model

- **Dashboard / admin API** — session cookie (`cv_session`, HttpOnly + SameSite=Strict
  + Secure-when-TLS), 12 h sliding expiry. Auth via username + bcrypt-12 +
  optional TOTP. Roles: admin / operator / viewer. Deletion of the last admin
  is refused.
- **Agent endpoints** (`ping`, `report`, `task_result`, `agent_ws`) — TOFU
  token issued on first contact, stored in `pcs.token`, validated with
  `subtle.ConstantTimeCompare`. Server returns `agent_token` in the response
  if no token is currently stored for the hostname; the agent persists it to
  `C:\ProgramData\Corrivex\config.json`.
- **Bootstrap / agent download** — gated by the allowed-domains list.
- **Transport** — HTTP by default; HTTPS by passing a cert + key (any standard
  PEM, e.g. ACME, internal CA). Reverse-proxy works equally well.
- **No emojis as icons**; SVGs only. Cookie respects `prefers-reduced-motion`.

## CVE scanning

On a 6-hour cycle (configurable via the `cve_scan_interval_hours` setting),
the server walks every unique `(package_id, version)` pair in the per-host
`installed_software` inventory and queries public CVE feeds:

1. **[OSV.dev](https://osv.dev)** first — free, no key, no rate limit in
   practice. Good coverage of OSS packages reachable via winget.
2. **[NVD 2.0](https://nvd.nist.gov/developers/vulnerabilities)** on OSV
   miss — the authoritative source for Windows desktop apps. Queried by
   CPE (`vendor:product`). Rate-limited to 5 req / 30 s without a key; set
   `NVD_API_KEY` to raise it to 50 / 30 s.
3. **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**
   refreshed daily. Any matching CVE gets a red **KEV** chip in the UI.

Results are cached per `(package_id, version)` — not per host — so a fleet
of 100 hosts all running the same Firefox build costs exactly one API
query per scan cycle. TTL defaults to 24 h (`cve_cache_ttl_hours` setting).

### Winget-ID → CPE mapping

NVD CPE names are notoriously inconsistent (`Notepad++.Notepad++` →
`notepad++:notepad++`, but `Mozilla.Firefox` → `mozilla:firefox`). The
scanner ships a hand-curated Go map (`internal/cve/mapper.go`) covering the
~80 most common winget IDs. Unmapped IDs are skipped for NVD (to avoid
false positives from fuzzy guesses) but still queried against OSV.

To extend the mapping without rebuilding, paste into **Settings → CVE
mappings** — one entry per line:

```
OBSProject.OBSStudio  obsproject:obs_studio
MyVendor.MyApp        my-vendor:my_app
```

Lines starting with `#` are ignored.

### Where CVEs surface in the UI

- **Dashboard top bar** — red `CVEs: N · K KEV` chip when findings exist.
- **Device modal → Security tab** — every CVE affecting the host's
  installed software, sorted KEV-first then by severity. Each CVE links
  to its NVD page. Admins see a **Rescan** button that bypasses the 24 h
  cache and forces a full re-query.
- **Device modal → Winget tab** — each available-upgrade row shows a red
  chip `N CVEs · K crit · KEV` when the installed version has findings.
- **API** — `GET /api/?action=cve_findings&host=HOST`,
  `GET /api/?action=cve_summary`, `POST /api/?action=rescan_cves` (admin).

### Air-gapped deployments

Set `CVE_SCAN_ENABLED=false` to disable all outbound traffic to OSV / NVD /
CISA. The UI degrades gracefully — the top-bar badge stays hidden, the
Security tab shows a "No known CVEs" empty state, and no chips render on
the winget rows. Flipping the flag back on picks up on the next scanner
cycle.

## Build from source

Prerequisites:
- Go 1.23+
- (For the release zip on Windows) PowerShell 5.1+ or pwsh 7+
- (For Docker deployment) Docker 24+

### Using Make (Linux / macOS / Git-Bash on Windows)

```sh
make                       # build linux server, windows server, windows agent
make server-linux          # corrivex-server (linux/amd64)
make server-windows        # corrivex-server.exe (windows/amd64)
make agent-windows         # corrivex-agent.exe (windows/amd64)
make release-windows       # dist/corrivex-windows.zip
make tidy                  # go mod tidy
make test                  # go test ./...
make clean                 # remove ./bin and ./dist
make deploy HOST=root@1.2.3.4   # rsync + docker compose to a remote host
```

### Using PowerShell (native Windows)

```powershell
.\build.ps1                # all targets (server linux + windows + agent)
.\build.ps1 -Target server-windows
.\build.ps1 -Target agent-windows
.\build.ps1 -Release       # dist\corrivex-windows.zip
.\build.ps1 -Clean
```

### Manually

```sh
GOOS=linux   GOARCH=amd64 go build -o bin/corrivex-server     ./cmd/server
GOOS=windows GOARCH=amd64 go build -o bin/corrivex-server.exe ./cmd/server
GOOS=windows GOARCH=amd64 go build -o bin/corrivex-agent.exe  ./cmd/agent
```

The Linux Docker image is built by `docker compose build` — no Go toolchain
needed on the host, the multi-stage `Dockerfile` builds inside `golang:alpine`.

## CI / Release pipeline (GitHub Actions)

Two workflows live in `.github/workflows/`:

- **`ci.yml`** — runs on every push and PR to `main`. Vets, tests, and
  cross-compiles all three binary targets. Does not publish anything.
- **`release.yml`** — runs when you push a `vX.Y.Z` tag. Builds all
  binaries (with the version embedded), packages the Windows zip,
  generates SHA256 checksums, creates a GitHub Release with the
  changelog section auto-extracted from `versioning.md`, and pushes a
  multi-tag Docker image (`X.Y.Z` and `latest`) to Docker Hub.

### Required GitHub repo secrets

| Setting | Where | Value |
|---|---|---|
| `DOCKERHUB_USERNAME` | Settings → Secrets and variables → Actions → **Secrets** | Docker Hub account that owns the image repo |
| `DOCKERHUB_TOKEN`    | same as above | Docker Hub access token (https://hub.docker.com/settings/security) — *not* your password. Needs scope **Read, Write & Delete** so the workflow can update the repo's Overview tab from `DOCKERHUB.md`. (Read-Write also works; Read-Only does not.) |
| `DOCKERHUB_REPO`     | Settings → Secrets and variables → Actions → **Variables** *(optional)* | Override the image repo name; defaults to `<DOCKERHUB_USERNAME>/corrivex` |

### Cutting a release

```sh
./scripts/bump-version.sh 1.2.3   # updates version.go + both versioninfo.json + changelog stub
$EDITOR versioning.md             # replace the TODO stub with the real entry
git add -A
git commit -m "release 1.2.3"
git push origin main
git tag v1.2.3
git push origin v1.2.3
```

The release workflow validates that the tag matches `internal/version/version.go`
(catches the "forgot to bump" mistake), then builds and publishes everything.

Track progress in the **Actions** tab of the GitHub repo. The release lands at
`https://github.com/<owner>/Corrivex/releases/tag/v1.2.3`, the image at
`<DOCKERHUB_USERNAME>/corrivex:1.2.3` (and `:latest`).

## Reports

A dedicated top-level **Reports** dashboard tab surfaces three core data
sets in five output formats. All endpoints are session-gated (operator
role or above); the **Rescan** CVE action requires admin.

### Data sets

| Type | Source | Scope |
|---|---|---|
| `installed_software` | per-host winget inventory + history | fleet or single host |
| `local_admins` | `Get-LocalGroupMember` on every full scan | fleet (use the CSV to filter per host) |
| `cve_findings` | `installed_software` × `cve_cache` × CISA KEV | fleet or single host |

### Formats

| Format | Notes |
|---|---|
| **CSV** | UTF-8 with BOM so Excel reads it correctly on Windows. Raw rows, no summary band. |
| **JSON** | Pretty-printed, trivially parseable by external tools. |
| **HTML** | Standalone document, Swiss-modernist layout (Lexend + Source Sans 3, Trust-&-Authority palette on pure white). Has a tuned `@media print` stylesheet — users can Ctrl+P → Save as PDF in any browser if they prefer the web typography. |
| **PDF** | Server-generated via `johnfercher/maroto` (pure Go, no headless Chromium). Landscape A4 for `installed_software` and `cve_findings`, portrait for `local_admins`. UTF-8-safe — Slovak/Czech/Polish/German diacritics all render (custom embedded Go Regular/Bold + GoMono Regular/Bold TTF families). |
| **ZIP (per-host PDFs)** | Fleet-wide only. Server partitions rows by host, renders one PDF per host, and streams a zip bundle with `README.txt` (scope/date/build/host count) and `manifest.json` (host → filename → rows → bytes). Hosts with zero rows still get a courtesy "no findings" PDF so the archive is a complete fleet snapshot. |

### API

```
GET /api/?action=report&type=TYPE&format=FORMAT[&host=HOST]
GET /api/?action=reports_summary
```

- `type` — `installed_software` | `local_admins` | `cve_findings`
- `format` — `csv` | `json` | `html` | `pdf` | `pdfzip`
- `host` — optional, restricts to a single hostname
  (`installed_software` and `cve_findings` only).
  Omitted / empty means the entire fleet.
- `format=pdfzip` only makes sense without `host` — the dashboard button
  auto-disables when a single host is selected.

Download files are named
`corrivex_<type>_<scope>_<YYYYMMDD>.<ext>`; the per-host ZIP uses
`scope=per_host`. `Content-Disposition: attachment` for downloads;
`inline` for HTML so the browser renders it for `Ctrl+P`.

`reports_summary` returns the four counters shown on the Reports tab's
top cards:

```json
{
  "devices": 42,
  "installed_packages": 2610,
  "distinct_local_admins": 17,
  "open_cves": 58
}
```

### PDF design

Layout follows Swiss Modernism 2.0 (grid-based, mathematical spacing,
monochrome + single accent). Cover block carries a brand strip, title,
scope/date/build metadata; summary band with KV counters; alternating-
row data table with dash-break for narrow cells; per-page footer
`Corrivex | page n / N` plus the report title. Fonts are embedded Go
Regular/Bold (proportional) and GoMono Regular/Bold (monospace) — full
Unicode cmap so non-ASCII usernames and package names render correctly.

### No extra dependencies

PDF generation runs in-process with `johnfercher/maroto/v2` (pure Go,
no CGo). No headless browser, no sidecar container, no external fonts
downloaded at runtime. Everything needed ships with the binary.

## How it talks to itself (wire protocol)

Per-agent persistent WebSocket on `/api/?action=agent_ws`. Frames are JSON
objects with a `type` field.

```
agent → server                              server → agent
─────────────────                           ─────────────────
hello {hostname,token,domain,agent_sha256}  hello_ok {agent_token,agent_sha256}
report {action,packages,windows_updates,…}  task     {task:{id,type,package_id,…}}
task_result {task_id,result}                ping
log {line}                                  (writer also auto-pings every 25 s)
pong
```

Dashboard subscribers receive a parallel stream on `/api/?action=ws`:

```
{type:"hello"}                              connection ack
{type:"pc",       data:{…full PC row}}      pc state changed
{type:"pc_online",data:{hostname,online}}   agent connected/disconnected
{type:"pc_removed",data:{hostname}}         hard delete
{type:"task",     data:{…enriched task}}    task created / delivered / completed / failed
{type:"log",      data:{hostname,ts,line}}  agent log line
{type:"domain",   data:{action,domain}}     allow-list mutation
```

## License

Corrivex is **dual-licensed**:

- **AGPL v3** for open-source / homelab / company-internal use — see
  [`LICENSE`](LICENSE).
- **Commercial license** for vendors embedding Corrivex in proprietary
  products, MSPs offering it as a managed service, or any user who cannot
  accept the AGPL's network-copyleft (section 13) — see
  [`LICENSE.commercial.md`](LICENSE.commercial.md) for the matrix and
  contact details.
