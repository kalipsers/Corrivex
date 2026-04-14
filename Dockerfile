# syntax=docker/dockerfile:1.7

# --- stage 1: build the Windows agent (embedded into the server binary-side assets) ---
FROM golang:1.23-alpine AS build
WORKDIR /src

RUN apk add --no-cache git ca-certificates
ENV GOTOOLCHAIN=auto

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Read the canonical version from source so both binaries embed the same
# string in their --version output and (for the .exe) the Windows file
# properties.
RUN VERSION="$(awk -F'\"' '/^var Version =/{print $2; exit}' internal/version/version.go)" && \
    echo "Building Corrivex v${VERSION}" && \
    LDFLAGS="-s -w -X github.com/markov/corrivex/internal/version.Version=${VERSION}" && \
    # goversioninfo runs ON the build host (linux/amd64) and writes a .syso
    # that the windows build picks up — never set GOOS=windows for it.
    go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1 \
        -64 -o cmd/agent/resource_amd64.syso cmd/agent/versioninfo.json && \
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -ldflags="$LDFLAGS" -o /out/corrivex-agent.exe ./cmd/agent && \
    GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -ldflags="$LDFLAGS" -o /out/corrivex-server ./cmd/server

# --- stage 2: runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata curl && adduser -D -H -u 10001 corrivex
WORKDIR /app

COPY --from=build /out/corrivex-server /app/corrivex-server
COPY --from=build /out/corrivex-agent.exe /app/corrivex-agent.exe

USER corrivex
EXPOSE 8484
ENV AGENT_BIN=/app/corrivex-agent.exe \
    CORRIVEX_ADDR=:8484

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8484/healthz || exit 1

ENTRYPOINT ["/app/corrivex-server"]
