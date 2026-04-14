# Corrivex build entry points.
#
# Defaults assume Linux/macOS/Git-Bash with `make` available. Windows admins
# who don't have make can use ./build.ps1 instead — same set of targets.

GO         ?= go
VERSION    := $(shell awk -F'"' '/^var Version =/{print $$2; exit}' internal/version/version.go)
LDFLAGS    := -s -w -X github.com/markov/corrivex/internal/version.Version=$(VERSION)
GOFLAGS    ?= -trimpath -ldflags="$(LDFLAGS)"
BIN_DIR    ?= bin
DIST_DIR   ?= dist
HOST       ?=
GOVERSIONINFO ?= go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1

.DEFAULT_GOAL := all
.PHONY: all server-linux server-windows agent-windows release-windows \
        syso-server syso-agent syso-clean \
        clean tidy fmt vet test deploy docker-build docker-up docker-down version

# ---- Build targets --------------------------------------------------------

all: server-linux server-windows agent-windows ## Build every binary

version: ## Print the current Corrivex version
	@echo $(VERSION)

server-linux: $(BIN_DIR) ## Linux server (linux/amd64)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/corrivex-server ./cmd/server

server-windows: $(BIN_DIR) syso-server ## Windows server (windows/amd64)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/corrivex-server.exe ./cmd/server

agent-windows: $(BIN_DIR) syso-agent ## Windows agent (windows/amd64)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BIN_DIR)/corrivex-agent.exe ./cmd/agent

# Generate Windows file-properties .syso so the exe shows the correct
# Product version / File version in Explorer → Properties → Details.
# goversioninfo runs on the build host — never cross-compile it.
syso-server: cmd/server/versioninfo.json
	cd cmd/server && GOOS= GOARCH= $(GOVERSIONINFO) -64 -o resource_amd64.syso versioninfo.json

syso-agent: cmd/agent/versioninfo.json
	cd cmd/agent && GOOS= GOARCH= $(GOVERSIONINFO) -64 -o resource_amd64.syso versioninfo.json

syso-clean: ## remove generated .syso files
	rm -f cmd/server/resource_amd64.syso cmd/agent/resource_amd64.syso

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# ---- Release packaging ----------------------------------------------------

release-windows: server-windows agent-windows ## dist/corrivex-windows-X.Y.Z.zip
	@mkdir -p $(DIST_DIR)/_stage
	cp $(BIN_DIR)/corrivex-server.exe $(DIST_DIR)/_stage/
	cp $(BIN_DIR)/corrivex-agent.exe  $(DIST_DIR)/_stage/
	cp deploy/install-server.ps1      $(DIST_DIR)/_stage/
	cp README.md                      $(DIST_DIR)/_stage/README.md
	cp versioning.md                  $(DIST_DIR)/_stage/versioning.md
	cd $(DIST_DIR)/_stage && zip -r ../corrivex-windows-$(VERSION).zip ./* >/dev/null
	rm -rf $(DIST_DIR)/_stage
	@echo
	@echo "  → $(DIST_DIR)/corrivex-windows-$(VERSION).zip"
	@ls -lh $(DIST_DIR)/corrivex-windows-$(VERSION).zip

# ---- Code hygiene ---------------------------------------------------------

tidy: ## go mod tidy
	$(GO) mod tidy

fmt: ## gofmt -w on the whole module
	$(GO) fmt ./...

vet: ## go vet
	$(GO) vet ./...

test: ## go test ./...
	$(GO) test ./...

# ---- Docker / Linux deployment -------------------------------------------

docker-build: ## docker compose build (locally)
	docker compose build

docker-up: ## docker compose up -d (locally)
	docker compose up -d

docker-down: ## docker compose down (locally)
	docker compose down

deploy: ## rsync source to HOST and `docker compose up -d`. HOST=user@1.2.3.4
	@if [ -z "$(HOST)" ]; then echo "Usage: make deploy HOST=user@host"; exit 2; fi
	./deploy/deploy.sh $(HOST)

# ---- Cleanup --------------------------------------------------------------

clean: syso-clean ## remove ./bin and ./dist
	rm -rf $(BIN_DIR) $(DIST_DIR)

# ---- Help -----------------------------------------------------------------

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
