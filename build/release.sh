#!/usr/bin/env bash
# Bundle a Windows release zip: corrivex-server.exe + corrivex-agent.exe +
# install-server.ps1 + README.md, ready to drop on a Windows host.
#
# Usage: ./build/release.sh        # produces dist/corrivex-windows.zip
#
# This is the same thing as `make release-windows`; provided as a standalone
# script for environments that don't have make.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

BIN="$HERE/bin"
DIST="$HERE/dist"
STAGE="$DIST/_stage"
VERSION="$(awk -F'"' '/^var Version =/{print $2; exit}' internal/version/version.go)"
LDFLAGS="-s -w -X github.com/markov/corrivex/internal/version.Version=${VERSION}"
GOVERSIONINFO="github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1"

mkdir -p "$BIN" "$DIST"
rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "Building Corrivex v${VERSION} for windows/amd64..."

# Generate Windows file-properties .syso so Properties → Details shows the
# version. goversioninfo runs as the build host — never set GOOS=windows.
( cd cmd/server && GOOS= GOARCH= go run "$GOVERSIONINFO" -64 -o resource_amd64.syso versioninfo.json )
( cd cmd/agent  && GOOS= GOARCH= go run "$GOVERSIONINFO" -64 -o resource_amd64.syso versioninfo.json )

echo "Building corrivex-server.exe..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="$LDFLAGS" -o "$BIN/corrivex-server.exe" ./cmd/server

echo "Building corrivex-agent.exe..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="$LDFLAGS" -o "$BIN/corrivex-agent.exe" ./cmd/agent

cp "$BIN/corrivex-server.exe" "$STAGE/"
cp "$BIN/corrivex-agent.exe"  "$STAGE/"
cp "$HERE/deploy/install-server.ps1" "$STAGE/"
cp "$HERE/README.md" "$STAGE/README.md"
cp "$HERE/versioning.md" "$STAGE/versioning.md"

ZIP="$DIST/corrivex-windows-${VERSION}.zip"
rm -f "$ZIP"

to_winpath() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        # MSYS2 / Git-Bash MSYS_NO_PATHCONV trick: prefix with double slash to
        # block path mangling, then sed-style cleanup.
        echo "$1" | sed -E 's|^/([a-zA-Z])/|\1:/|; s|/|\\|g'
    fi
}

if command -v zip >/dev/null 2>&1; then
    (cd "$STAGE" && zip -r "$ZIP" ./* >/dev/null)
elif command -v powershell >/dev/null 2>&1; then
    SRC_WIN="$(to_winpath "$STAGE")\\*"
    DST_WIN="$(to_winpath "$ZIP")"
    powershell -NoProfile -Command "Compress-Archive -Path '$SRC_WIN' -DestinationPath '$DST_WIN' -Force"
else
    echo "ERROR: need either 'zip' or 'powershell' on PATH to package the archive" >&2
    exit 1
fi

rm -rf "$STAGE"
echo
ls -lh "$ZIP"
