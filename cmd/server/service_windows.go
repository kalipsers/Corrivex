//go:build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	winSvcName    = "CorrivexServer"
	winSvcDisplay = "Corrivex Server"
	winSvcDesc    = "Corrivex HTTP server (dashboard, API, agent hub)."
	winDataDir    = `C:\ProgramData\Corrivex\server`
	winConfigPath = `C:\ProgramData\Corrivex\server\config.json`
)

// maybeRunAsService returns true when the binary was launched by the SCM and
// the request to run as a service has been honoured. Otherwise returns false
// and the caller should run the server in the foreground.
func maybeRunAsService(opts ServerOptions) bool {
	inSvc, err := svc.IsWindowsService()
	if err != nil || !inSvc {
		return false
	}
	// Service mode — load options from config.json (the install command wrote
	// it). The opts arg is ignored because the SCM doesn't forward CLI flags.
	cfg := loadServiceConfig()
	go func() {
		err := svc.Run(winSvcName, &svcWrapper{opts: cfg})
		if err != nil {
			log.Printf("service run: %v", err)
		}
	}()
	// Block forever; svc.Run drives shutdown via Stop in the wrapper.
	select {}
}

type svcWrapper struct{ opts ServerOptions }

func (w *svcWrapper) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (ssec bool, errno uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runServer(ctx, w.opts)
		close(done)
	}()

	s <- svc.Status{State: svc.Running, Accepts: accepted}
loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			cancel()
			break loop
		}
	}
	<-done
	return
}

// -- install / uninstall / control -----------------------------------------

func runWindowsInstall() {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	addr := fs.String("addr", ":8484", "listen address")
	dbDriver := fs.String("db-driver", "sqlite", "mariadb or sqlite")
	dbPath := fs.String("db-path", filepath.Join(winDataDir, "corrivex.db"), "SQLite database file")
	dbHost := fs.String("db-host", "127.0.0.1", "MariaDB host")
	dbPort := fs.Int("db-port", 3306, "MariaDB port")
	dbName := fs.String("db-name", "corrivex", "MariaDB database")
	dbUser := fs.String("db-user", "corrivex", "MariaDB user")
	dbPass := fs.String("db-pass", "", "MariaDB password")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (PEM)")
	tlsKey := fs.String("tls-key", "", "TLS private key file (PEM)")
	apiSecret := fs.String("api-secret", "", "shared secret for agent endpoints (optional)")
	noDomain := fs.Bool("no-domain-check", false, "accept agents without checking allow-list")
	fs.Parse(os.Args[2:])

	if err := os.MkdirAll(winDataDir, 0o755); err != nil {
		fatal("mkdir %s: %v", winDataDir, err)
	}

	exePath, agentPath, err := stageBinaries()
	if err != nil {
		fatal("stage binaries: %v", err)
	}

	opts := ServerOptions{
		Addr: *addr, TLSCert: *tlsCert, TLSKey: *tlsKey,
		APISecret: *apiSecret, AgentBin: agentPath,
		History: 50, NoDomain: *noDomain,
		DBDriver: *dbDriver, DBPath: *dbPath,
		DBHost: *dbHost, DBPort: *dbPort, DBName: *dbName,
		DBUser: *dbUser, DBPass: *dbPass,
	}
	saveServiceConfig(opts)

	if err := installWindowsService(exePath); err != nil {
		fatal("install service: %v", err)
	}
	fmt.Printf("Service %q installed.\n", winSvcName)

	if err := startWindowsService(); err != nil {
		fmt.Fprintf(os.Stderr, "Service installed but did not start cleanly: %v\n", err)
		os.Exit(1)
	}
	scheme := "http"
	if opts.TLSCert != "" {
		scheme = "https"
	}
	fmt.Printf("Started. Dashboard: %s://localhost%s/\n", scheme, opts.Addr)
}

func runWindowsUninstall() {
	stopWindowsService()
	m, err := mgr.Connect()
	if err != nil {
		fatal("service manager: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(winSvcName)
	if err != nil {
		fatal("open service: %v", err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		fatal("delete service: %v", err)
	}
	eventlog.Remove(winSvcName)
	fmt.Printf("Service %q removed.\n", winSvcName)
}

func runWindowsCtl(action string) {
	switch action {
	case "start":
		if err := startWindowsService(); err != nil {
			fatal("start: %v", err)
		}
		fmt.Println("Started.")
	case "stop":
		if err := stopWindowsService(); err != nil {
			fatal("stop: %v", err)
		}
		fmt.Println("Stopped.")
	}
}

func runWindowsStatus() {
	m, err := mgr.Connect()
	if err != nil {
		fatal("service manager: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(winSvcName)
	if err != nil {
		fmt.Println("not installed")
		return
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		fatal("query: %v", err)
	}
	fmt.Printf("service=%s state=%d\n", winSvcName, st.State)
}

func installWindowsService(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if existing, err := m.OpenService(winSvcName); err == nil {
		stopWindowsService()
		existing.Delete()
		existing.Close()
		time.Sleep(500 * time.Millisecond)
	}
	s, err := m.CreateService(winSvcName, exePath, mgr.Config{
		DisplayName: winSvcDisplay,
		Description: winSvcDesc,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return err
	}
	defer s.Close()
	r := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 120 * time.Second},
	}
	s.SetRecoveryActions(r, 86400)
	eventlog.InstallAsEventCreate(winSvcName, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

func startWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(winSvcName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func stopWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(winSvcName)
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for status.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return err
		}
	}
	return nil
}

// -- config persistence ----------------------------------------------------

func saveServiceConfig(opts ServerOptions) {
	b, _ := json.MarshalIndent(opts, "", "  ")
	_ = os.WriteFile(winConfigPath, b, 0o644)
}

func loadServiceConfig() ServerOptions {
	b, err := os.ReadFile(winConfigPath)
	if err != nil {
		log.Printf("no service config at %s: %v", winConfigPath, err)
		// Sensible defaults so the service still starts.
		return ServerOptions{
			Addr: ":8484", DBDriver: "sqlite",
			DBPath: filepath.Join(winDataDir, "corrivex.db"),
			History: 50,
		}
	}
	var o ServerOptions
	if err := json.Unmarshal(b, &o); err != nil {
		log.Printf("bad service config: %v", err)
	}
	return o
}

// -- staging ---------------------------------------------------------------

// stageBinaries copies the running corrivex-server.exe and (if found next to
// it) corrivex-agent.exe into the install directory so the service has a
// stable, writable location even when started from a downloads folder.
func stageBinaries() (serverPath, agentPath string, err error) {
	self, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	srvDest := filepath.Join(winDataDir, "corrivex-server.exe")
	if !sameFileWin(self, srvDest) {
		if err := copyFileWin(self, srvDest); err != nil {
			return "", "", fmt.Errorf("copy server: %w", err)
		}
	}
	candAgent := filepath.Join(filepath.Dir(self), "corrivex-agent.exe")
	if _, err := os.Stat(candAgent); err == nil {
		agentDest := filepath.Join(winDataDir, "corrivex-agent.exe")
		if !sameFileWin(candAgent, agentDest) {
			if err := copyFileWin(candAgent, agentDest); err != nil {
				return "", "", fmt.Errorf("copy agent: %w", err)
			}
		}
		agentPath = agentDest
	}
	return srvDest, agentPath, nil
}

func sameFileWin(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	return strings.EqualFold(aa, bb)
}

func copyFileWin(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
