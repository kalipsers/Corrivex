// Command corrivex-agent runs as a Windows Service that polls Corrivex for tasks.
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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/markov/corrivex/internal/agent"
	"github.com/markov/corrivex/internal/version"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	defaultSvcName     = "CorrivexAgent"
	defaultDisplayName = "Corrivex Agent"
	defaultDesc        = "Corrivex endpoint agent — polls the Corrivex server for pending winget tasks."
	dataDir            = `C:\ProgramData\Corrivex`
	configFile         = `C:\ProgramData\Corrivex\config.json`
	logFile            = `C:\ProgramData\Corrivex\agent.log`
)

func main() {
	if len(os.Args) < 2 {
		// Running as a service (no args) or invoked by SCM?
		inService, err := svc.IsWindowsService()
		if err == nil && inService {
			runService(defaultSvcName, false)
			return
		}
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

	switch cmd {
	case "install":
		installCmd()
	case "uninstall", "remove":
		uninstallCmd()
	case "start":
		startCmd()
	case "stop":
		controlCmd(svc.Stop)
	case "status":
		statusCmd()
	case "run":
		runForeground()
	case "debug":
		runForeground()
	case "help", "-h", "--help":
		usage()
	case "version", "--version", "-v":
		fmt.Println("corrivex-agent " + version.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Corrivex agent
Usage:
  corrivex-agent.exe install --server=URL [--check-min=N] [--scan-hrs=N] [--svc-name=NAME]
  corrivex-agent.exe uninstall
  corrivex-agent.exe start|stop|status
  corrivex-agent.exe run         (run in the foreground)`)
}

// -- install/uninstall -----------------------------------------------------

func installCmd() {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	server := fs.String("server", "", "Corrivex server URL (required)")
	checkMin := fs.Int("check-min", 1, "task poll interval in minutes")
	scanHrs := fs.Int("scan-hrs", 24, "full-scan interval in hours")
	svcName := fs.String("svc-name", defaultDisplayName, "Windows service display name")
	apiSecret := fs.String("api-secret", "", "shared secret for the server API (optional)")
	fs.Parse(os.Args[1:])

	if *server == "" {
		fatal("--server is required")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		fatal("mkdir %s: %v", dataDir, err)
	}

	cfg := agent.Config{
		Server: *server, CheckMin: *checkMin, ScanHrs: *scanHrs,
		ServiceName: *svcName, APISecret: *apiSecret,
	}
	// Preserve the TOFU token from a previous install so we don't get
	// locked out of the server (which remembers the token per-hostname).
	if existing, err := os.ReadFile(configFile); err == nil {
		var prev agent.Config
		if json.Unmarshal(existing, &prev) == nil && prev.AgentToken != "" {
			cfg.AgentToken = prev.AgentToken
			fmt.Println("Preserved existing agent token.")
		}
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configFile, b, 0o644); err != nil {
		fatal("write config: %v", err)
	}

	exePath, err := copyBinaryToDataDir()
	if err != nil {
		fatal("copy binary: %v", err)
	}

	internalName := toServiceName(*svcName)
	if err := installService(internalName, *svcName, exePath); err != nil {
		fatal("install service: %v", err)
	}
	fmt.Printf("Installed service %q (display: %q)\n", internalName, *svcName)

	if err := startService(internalName); err != nil {
		fmt.Fprintf(os.Stderr, "Service installed but did not start cleanly: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service started.")
}

func uninstallCmd() {
	svcName := readSvcName()
	// best-effort stop
	controlService(svcName, svc.Stop, 10*time.Second)
	m, err := mgr.Connect()
	if err != nil {
		fatal("service manager: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		fatal("open service %s: %v", svcName, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		fatal("delete service: %v", err)
	}
	eventlog.Remove(svcName)
	fmt.Printf("Service %q removed.\n", svcName)
}

func controlCmd(c svc.Cmd) {
	name := readSvcName()
	if err := controlService(name, c, 15*time.Second); err != nil {
		fatal("control: %v", err)
	}
	fmt.Println("OK")
}

func startCmd() {
	if err := startService(readSvcName()); err != nil {
		fatal("start: %v", err)
	}
	fmt.Println("Started.")
}

func statusCmd() {
	name := readSvcName()
	m, err := mgr.Connect()
	if err != nil {
		fatal("service manager: %v", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		fmt.Println("not installed")
		return
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		fatal("query: %v", err)
	}
	fmt.Printf("service=%s state=%d\n", name, st.State)
}

// -- binary/service helpers ------------------------------------------------

func copyBinaryToDataDir() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dataDir, "corrivex-agent.exe")
	if sameFile(self, dest) {
		return dest, nil
	}
	in, err := os.Open(self)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	return dest, nil
}

func sameFile(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	return strings.EqualFold(aa, bb)
}

func installService(name, display, exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	// Remove existing service (fresh install semantics)
	if existing, err := m.OpenService(name); err == nil {
		controlService(name, svc.Stop, 8*time.Second)
		existing.Delete()
		existing.Close()
		time.Sleep(500 * time.Millisecond)
	}
	s, err := m.CreateService(name, exePath, mgr.Config{
		DisplayName:      display,
		Description:      defaultDesc,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "",
	})
	if err != nil {
		return err
	}
	defer s.Close()
	// Auto-restart on failure
	r := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 120 * time.Second},
	}
	s.SetRecoveryActions(r, 86400)
	// Event log
	eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	return nil
}

func startService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func controlService(name string, c svc.Cmd, timeout time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Control(c)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for status.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return err
		}
	}
	return nil
}

func toServiceName(display string) string {
	// Windows service name can't contain spaces; derive from display.
	r := strings.NewReplacer(" ", "", "\t", "", "/", "", "\\", "")
	n := r.Replace(display)
	if n == "" {
		n = defaultSvcName
	}
	return n
}

func readSvcName() string {
	b, err := os.ReadFile(configFile)
	if err != nil {
		return defaultSvcName
	}
	var cfg agent.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return defaultSvcName
	}
	if cfg.ServiceName == "" {
		return defaultSvcName
	}
	return toServiceName(cfg.ServiceName)
}

// -- service handler --------------------------------------------------------

type corrivexSvc struct{}

func (w *corrivexSvc) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (ssec bool, errno uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	cfg := loadConfig()
	logf := fileLogger()
	run := agent.New(cfg, dataDir, logf)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		run.Run(ctx)
		close(done)
	}()

	s <- svc.Status{State: svc.Running, Accepts: accepted}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				break loop
			}
		}
	}
	<-done
	return
}

func runService(name string, isDebug bool) {
	var err error
	if isDebug {
		err = svc.Run(name, &corrivexSvc{})
	} else {
		err = svc.Run(name, &corrivexSvc{})
	}
	if err != nil {
		log.Printf("service run: %v", err)
	}
}

func runForeground() {
	cfg := loadConfig()
	logf := func(f string, a ...any) { log.Printf(f, a...) }
	run := agent.New(cfg, dataDir, logf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run.Run(ctx)
}

func loadConfig() agent.Config {
	b, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("no config at %s: %v", configFile, err)
		return agent.Config{CheckMin: 1, ScanHrs: 24}
	}
	var c agent.Config
	if err := json.Unmarshal(b, &c); err != nil {
		log.Printf("bad config: %v", err)
	}
	if c.CheckMin <= 0 {
		c.CheckMin = 1
	}
	if c.ScanHrs <= 0 {
		c.ScanHrs = 24
	}
	return c
}

func fileLogger() func(string, ...any) {
	os.MkdirAll(dataDir, 0o755)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return func(format string, args ...any) { log.Printf(format, args...) }
	}
	logger := log.New(f, "", log.LstdFlags)
	return func(format string, args ...any) { logger.Printf(format, args...) }
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// suppress "unused import" if exec not used directly here.
var _ = exec.Command
