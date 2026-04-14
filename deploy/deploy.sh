#!/usr/bin/env bash
# Deploy Corrivex server from this repo to a remote Docker host.
#
# Usage:
#   ./deploy/deploy.sh user@host
#   CORRIVEX_HOST=user@host ./deploy/deploy.sh
#
# Optional env:
#   CORRIVEX_REMOTE_DIR   defaults to /opt/corrivex
set -euo pipefail

TARGET="${1:-${CORRIVEX_HOST:-}}"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 user@host    (or set CORRIVEX_HOST=user@host)" >&2
  exit 2
fi
REMOTE_DIR="${CORRIVEX_REMOTE_DIR:-/opt/corrivex}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

echo "[1/4] sync source → ${TARGET}:${REMOTE_DIR}"
ssh "$TARGET" "mkdir -p ${REMOTE_DIR}"
# Rsync if available; fall back to scp.
if command -v rsync >/dev/null 2>&1; then
  rsync -az --delete \
    --exclude bin/ --exclude .git/ --exclude '*.exe' --exclude node_modules/ \
    ./ "${TARGET}:${REMOTE_DIR}/"
else
  tar --exclude=bin --exclude=.git --exclude='*.exe' -cz . | \
    ssh "$TARGET" "cd ${REMOTE_DIR} && tar xz"
fi

echo "[2/4] ensure .env"
ssh "$TARGET" "cd ${REMOTE_DIR} && if [ ! -f .env ]; then
  PASS=\$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
  ROOT=\$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
  cat >.env <<EOF
DB_NAME=corrivex
DB_USER=corrivex
DB_PASS=\$PASS
DB_ROOT_PASS=\$ROOT
API_SECRET=
EOF
  echo 'Created .env (random creds).'
fi"

echo "[3/4] docker compose build & up"
ssh "$TARGET" "cd ${REMOTE_DIR} && docker compose build && docker compose up -d"

echo "[4/4] health"
ssh "$TARGET" "for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS http://127.0.0.1:8484/healthz >/dev/null 2>&1; then echo 'server healthy'; exit 0; fi
  sleep 2
done; docker compose -f ${REMOTE_DIR}/docker-compose.yml logs --tail=80 server; exit 1"

echo "Done. http://${TARGET#*@}:8484/"
