// Command corrivex-server is the Corrivex HTTP server.
//
// It runs the same code on Linux and Windows. On Windows it also exposes
// install/uninstall/run subcommands that register the binary as a service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/markov/corrivex/internal/api"
	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/events"
	"github.com/markov/corrivex/internal/hub"
	"github.com/markov/corrivex/internal/version"
	"github.com/markov/corrivex/internal/web"
)

// ServerOptions is the runtime configuration of one server instance.
type ServerOptions struct {
	Addr      string
	TLSCert   string
	TLSKey    string
	APISecret string
	AgentBin  string
	History   int
	NoDomain  bool

	DBDriver string
	// SQLite
	DBPath string
	// MariaDB
	DBHost, DBName, DBUser, DBPass string
	DBPort                         int
}

func main() {
	// On Windows, peek at argv[1] to support `install / uninstall / run`.
	if runtime.GOOS == "windows" && len(os.Args) >= 2 {
		switch os.Args[1] {
		case "install":
			runWindowsInstall()
			return
		case "uninstall", "remove":
			runWindowsUninstall()
			return
		case "status":
			runWindowsStatus()
			return
		case "start":
			runWindowsCtl("start")
			return
		case "stop":
			runWindowsCtl("stop")
			return
		case "run":
			// fall through to normal main, treating remaining args as flags.
			os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		case "help", "-h", "--help":
			usage()
			return
		case "version", "--version", "-v":
			fmt.Println("corrivex-server " + version.Version)
			return
		}
	}
	// Same on Linux: --version short-circuits before flag parsing.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println("corrivex-server " + version.Version)
			return
		}
	}

	opts := parseOptions()

	// On Windows, if the SCM started us, run as a service. Otherwise foreground.
	if runtime.GOOS == "windows" {
		if maybeRunAsService(opts) {
			return
		}
	}
	runServer(context.Background(), opts)
}

func usage() {
	fmt.Fprintln(os.Stderr, `Corrivex server
Usage:
  corrivex-server.exe                  run in the foreground (linux & windows)
  corrivex-server.exe install   ...    register Windows service (Windows only)
  corrivex-server.exe uninstall        remove Windows service
  corrivex-server.exe start | stop     control the service
  corrivex-server.exe status           query service state

Common flags (use after `+"`run`"+` on Windows):
  --addr=:8484
  --db-driver=sqlite|mariadb
  --db-path=PATH                       (sqlite)
  --db-host/--db-port/--db-name/--db-user/--db-pass   (mariadb)
  --tls-cert=PATH --tls-key=PATH       enable HTTPS
  --agent-bin=PATH                     embedded agent .exe to serve
  --api-secret=SECRET                  optional shared secret`)
}

func parseOptions() ServerOptions {
	defaultDriver := "mariadb"
	if runtime.GOOS == "windows" {
		defaultDriver = "sqlite"
	}
	defaultDBPath := "corrivex.db"
	if runtime.GOOS == "windows" {
		defaultDBPath = `C:\ProgramData\Corrivex\server\corrivex.db`
	}

	addr := flag.String("addr", envOr("CORRIVEX_ADDR", ":8484"), "listen address")
	dbDriver := flag.String("db-driver", envOr("DB_DRIVER", defaultDriver), "mariadb or sqlite")
	dbPath := flag.String("db-path", envOr("DB_PATH", defaultDBPath), "SQLite database file")
	dbHost := flag.String("db-host", envOr("DB_HOST", "127.0.0.1"), "MariaDB host")
	dbPort := flag.Int("db-port", envOrInt("DB_PORT", 3306), "MariaDB port")
	dbName := flag.String("db-name", envOr("DB_NAME", "corrivex"), "MariaDB database")
	dbUser := flag.String("db-user", envOr("DB_USER", "corrivex"), "MariaDB user")
	dbPass := flag.String("db-pass", envOr("DB_PASS", ""), "MariaDB password")
	requireDomain := flag.Bool("require-domain", envOrBool("REQUIRE_DOMAIN_CHECK", true), "require enrollment domain to be in allow list")
	historyKeep := flag.Int("history-keep", envOrInt("HISTORY_KEEP", 50), "reports per (host,action) to keep")
	apiSecret := flag.String("api-secret", envOr("API_SECRET", ""), "shared secret for agent endpoints (empty = disabled)")
	agentPath := flag.String("agent-bin", envOr("AGENT_BIN", defaultAgentBinPath()), "path to corrivex-agent.exe to serve")
	tlsCert := flag.String("tls-cert", envOr("TLS_CERT", ""), "TLS certificate file (PEM); empty = HTTP only")
	tlsKey := flag.String("tls-key", envOr("TLS_KEY", ""), "TLS private key file (PEM); empty = HTTP only")
	flag.Parse()
	return ServerOptions{
		Addr: *addr, TLSCert: *tlsCert, TLSKey: *tlsKey,
		APISecret: *apiSecret, AgentBin: *agentPath,
		History: *historyKeep, NoDomain: !*requireDomain,
		DBDriver: *dbDriver, DBPath: *dbPath,
		DBHost: *dbHost, DBPort: *dbPort, DBName: *dbName,
		DBUser: *dbUser, DBPass: *dbPass,
	}
}

// defaultAgentBinPath returns the default location to look for the embedded
// agent .exe — alongside the server binary on Windows, so the installer
// places both in the same folder.
func defaultAgentBinPath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	cand := filepath.Join(filepath.Dir(self), "corrivex-agent.exe")
	if _, err := os.Stat(cand); err == nil {
		return cand
	}
	return ""
}

func runServer(ctx context.Context, opts ServerOptions) {
	var agentBin []byte
	if opts.AgentBin != "" {
		b, err := os.ReadFile(opts.AgentBin)
		if err != nil {
			log.Fatalf("read agent binary %s: %v", opts.AgentBin, err)
		}
		agentBin = b
		abs, _ := filepath.Abs(opts.AgentBin)
		log.Printf("loaded agent binary: %s (%d bytes)", abs, len(b))
	} else {
		log.Printf("WARNING: no --agent-bin provided; /api/?action=agent.exe will return 500")
	}

	cfg := db.Config{
		Driver:   db.Driver(opts.DBDriver),
		Host:     opts.DBHost, Port: opts.DBPort, Name: opts.DBName,
		User:     opts.DBUser, Pass: opts.DBPass,
		Path:     opts.DBPath,
		CheckDom: !opts.NoDomain, Keep: opts.History,
	}
	database, err := db.Open(cfg)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("Corrivex server v%s starting", version.Version)
	log.Printf("database ready (%s)", cfg.Driver)

	broker := events.New()
	connHub := hub.New()

	dash, err := web.NewDashboard(database, connHub)
	if err != nil {
		log.Fatalf("dashboard: %v", err)
	}
	apiSrv := api.New(database, agentBin, opts.APISecret, broker, connHub)

	mux := http.NewServeMux()
	mux.Handle("/api/", apiSrv.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("/", dash)

	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	tls := opts.TLSCert != "" && opts.TLSKey != ""
	go func() {
		scheme := "http"
		if tls {
			scheme = "https"
		}
		log.Printf("listening on %s://%s (driver=%s)", scheme, opts.Addr, cfg.Driver)
		var err error
		if tls {
			err = srv.ListenAndServeTLS(opts.TLSCert, opts.TLSKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case <-stop:
	case <-ctx.Done():
	}
	log.Println("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%-6s %-24s %s %s", r.Method, r.URL.Path+"?"+r.URL.RawQuery, r.RemoteAddr, time.Since(start))
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envOrInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envOrBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		return v == "1" || v == "true" || v == "yes" || v == "on"
	}
	return def
}
