# Corrivex Server

Centralised **winget** + **Windows Update** orchestration for Windows endpoints,
with a real-time dashboard, role-based admin UI, and a single-binary agent.

This image runs the **server** half of Corrivex — the dashboard, HTTP API,
agent hub, and storage layer (MariaDB or SQLite). The matching **Windows agent**
(`corrivex-agent.exe`) and the **server-on-Windows** build (`corrivex-server.exe`)
are published as GitHub Release artifacts:

➜ **https://github.com/kalipsers/Corrivex/releases**

Source, full docs, license: **https://github.com/kalipsers/Corrivex**

---

## Image tags

| Tag | Meaning |
|---|---|
| `latest` | Most recent stable release. Tracks `:X.Y.Z` after each tag. |
| `X.Y.Z`  | Pinned to a specific SemVer release. **Recommended for production.** |

Browse all tags: <https://hub.docker.com/r/kalipserproit/corrivex/tags>

---

## Quickstart with Docker Compose

Save as **`docker-compose.yml`**:

```yaml
name: corrivex

services:
  db:
    image: mariadb:11
    restart: unless-stopped
    environment:
      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASS}
      MARIADB_DATABASE: ${DB_NAME}
      MARIADB_USER: ${DB_USER}
      MARIADB_PASSWORD: ${DB_PASS}
      TZ: ${TZ:-UTC}
    volumes:
      - corrivex_db:/var/lib/mysql
    healthcheck:
      test: ["CMD-SHELL", "mariadb-admin ping -h 127.0.0.1 -p$${MARIADB_ROOT_PASSWORD} --silent"]
      interval: 10s
      timeout: 5s
      retries: 12

  server:
    image: ${CORRIVEX_IMAGE:-kalipserproit/corrivex:latest}
    restart: unless-stopped
    pull_policy: always
    depends_on:
      db:
        condition: service_healthy
    environment:
      CORRIVEX_ADDR: ":8484"
      DB_HOST: db
      DB_PORT: "3306"
      DB_NAME: ${DB_NAME}
      DB_USER: ${DB_USER}
      DB_PASS: ${DB_PASS}
      REQUIRE_DOMAIN_CHECK: "true"
      HISTORY_KEEP: "50"
      API_SECRET: ${API_SECRET:-}
      TZ: ${TZ:-UTC}
    ports:
      - "8484:8484"

volumes:
  corrivex_db:
```

Save as **`.env`** (replace the placeholder strings with random 32-char values):

```dotenv
DB_NAME=corrivex
DB_USER=corrivex
DB_PASS=change-me-please-32-random-chars
DB_ROOT_PASS=change-me-please-32-random-chars
API_SECRET=

# IANA zone — applied to both the MariaDB and Corrivex-server containers
# so DB timestamps and Go's time.Now() agree. Default UTC.
TZ=UTC
```

Then:

```sh
docker compose pull
docker compose up -d
```

Browse **<http://your-host:8484/>** — first visit redirects to the *Create
first admin* form. After creating the admin, go to **Allowed domains** and
either add your AD domain (e.g. `contoso.local`, `WORKGROUP`) or enter a
literal `*` to permit any domain. Then open **Enroll device** for the
PowerShell one-liner you run on each Windows endpoint.

### Pin a specific release

```sh
CORRIVEX_IMAGE=kalipserproit/corrivex:1.2.0 docker compose up -d
```

### Upgrade

```sh
docker compose pull && docker compose up -d
```

---

## Environment variables

Server-side configuration (set in `.env` or directly on `environment:`):

| Var | Default | Purpose |
|---|---|---|
| `CORRIVEX_ADDR` | `:8484` | Listen address |
| `DB_DRIVER` | `mariadb` | `mariadb` or `sqlite` |
| `DB_HOST` | `db` | MariaDB host |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_NAME` | `corrivex` | MariaDB database |
| `DB_USER` | `corrivex` | MariaDB user |
| `DB_PASS` | *(empty)* | MariaDB password |
| `DB_PATH` | `corrivex.db` | SQLite file path (when `DB_DRIVER=sqlite`) |
| `REQUIRE_DOMAIN_CHECK` | `true` | Gate enrollment on the allow list |
| `HISTORY_KEEP` | `50` | Reports per (host, action) to retain |
| `API_SECRET` | *(empty)* | Optional shared secret for agent endpoints |
| `TLS_CERT` | *(empty)* | Path to PEM cert (enables HTTPS) |
| `TLS_KEY`  | *(empty)* | Path to PEM key |
| `TZ` | `UTC` | IANA timezone for DB + server. Set on **both** services so `CURRENT_TIMESTAMP` and `time.Now()` stay in sync. |

---

## What's in the image

- `/app/corrivex-server` — Linux/amd64 server binary
- `/app/corrivex-agent.exe` — Windows agent that the server serves at
  `/api/?action=agent.exe` for the bootstrap one-liner
- Healthcheck: `curl -fsS http://127.0.0.1:8484/healthz`
- Runs as the unprivileged user `corrivex` (UID 10001)

The image is built on `alpine:3.20`, ~25 MB compressed. Pure-Go binaries —
no glibc dependency, no CGO.

---

## Architecture

```
     ┌──────────────────────┐
     │  Admin web browser   │
     └──────────┬───────────┘
                │  HTTP/HTTPS + WS
                ▼
   ┌──────────────────────────┐
   │   corrivex-server image  │   ← this image
   │   ├─ dashboard           │
   │   ├─ /api/  + WebSocket  │
   │   └─ MariaDB or SQLite   │
   └────────────┬─────────────┘
                │  WSS agent_ws (per host, persistent)
   ┌────────────┴───────────────┬─────────────┬──────────── …
   ▼                            ▼             ▼
 PC1                          PC2           SRV1
 corrivex-agent.exe           corrivex-     corrivex-
 (winget + WU + tasks)        agent.exe     agent.exe
```

---

## License

Dual-licensed:

- **AGPL v3** for open-source / homelab / company-internal use
- **Commercial license** for vendors embedding Corrivex in proprietary
  products, MSPs offering it as a managed service, or any user who cannot
  accept the AGPL's network-copyleft (section 13)

See the licence files in the source repo:
**<https://github.com/kalipsers/Corrivex>**
