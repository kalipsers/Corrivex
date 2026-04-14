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

The recommended deployment for fleets.

```sh
# Clone, then on the target Docker host:
mkdir -p /opt/corrivex && cd /opt/corrivex

# (a) drop the source tree here
# (b) create .env  (random creds)
PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
ROOT=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
cat > .env <<EOF
DB_NAME=corrivex
DB_USER=corrivex
DB_PASS=$PASS
DB_ROOT_PASS=$ROOT
API_SECRET=
EOF

# (c) build + run
docker compose build
docker compose up -d
```

Browse `http://your-host:8484/`. The first visit redirects to the **Create
first admin** form. Create the admin, then go to **Allowed domains** and add
your AD domain(s). Show **Enroll device** to get the bootstrap one-liner.

`deploy/deploy.sh root@HOST` is a wrapper that rsyncs the source, creates
`.env` if missing, builds, and brings the stack up.

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
