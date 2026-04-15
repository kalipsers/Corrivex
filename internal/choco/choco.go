//go:build windows

// Package choco shells out to the chocolatey CLI (choco.exe). It mirrors
// the shape of internal/winget so the agent can treat the two as
// interchangeable package-manager backends.
//
// Chocolatey covers roughly 10x more Windows desktop packages than winget
// and ships per-package silent-install scripts curated by each maintainer,
// which is why Corrivex uses it as the second cascade layer.
package choco

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Package describes one Chocolatey row. Layout matches winget.Package so
// the agent's merge logic stays symmetric.
type Package struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Available string `json:"available"`
	Source    string `json:"source"`
}

// Find returns the path to choco.exe, or empty if not installed.
func Find() string {
	if p, err := exec.LookPath("choco.exe"); err == nil {
		return p
	}
	// Standard Chocolatey install directory.
	for _, cand := range []string{
		os.Getenv("ChocolateyInstall") + `\bin\choco.exe`,
		`C:\ProgramData\chocolatey\bin\choco.exe`,
	} {
		if cand == `\bin\choco.exe` {
			continue
		}
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

// IsInstalled is a convenience wrapper for call sites that don't care
// about the path.
func IsInstalled() bool { return Find() != "" }

// hideWindow detaches the child's console so the agent running as a
// service doesn't leak a flash of cmd.exe when it shells out.
func hideWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}

// runChoco runs `choco <args...>` and returns the combined stdout/stderr
// plus the exit code. Follows the same convention as winget.runWinget2.
// Flags `--yes`, `--no-progress`, and `--limit-output` (where relevant)
// are appended by the caller — this helper only handles process launch.
func runChoco(args ...string) (string, int, error) {
	path := Find()
	if path == "" {
		return "", -1, fmt.Errorf("chocolatey not installed")
	}
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = hideWindow()
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ex, ok := err.(*exec.ExitError); ok {
			code = ex.ExitCode()
		} else {
			return string(out), -1, err
		}
	}
	return string(out), code, nil
}

// ListInstalled parses `choco list --local-only --limit-output` to produce
// a Package slice. Layout:   name|version   one row per line.
// Limit-output mode suppresses the noisy header/footer.
func ListInstalled() ([]Package, error) {
	if !IsInstalled() {
		return nil, nil
	}
	out, code, err := runChoco("list", "--local-only", "--limit-output", "--no-color")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("choco list exit %d: %s", code, firstLine(out))
	}
	var pkgs []Package
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "chocolatey v") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		id := strings.TrimSpace(parts[0])
		ver := strings.TrimSpace(parts[1])
		if id == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:    id,
			ID:      id,
			Version: ver,
			Source:  "chocolatey",
		})
	}
	return pkgs, nil
}

// ListUpgrades parses `choco outdated --limit-output`. Layout:
//   name|current|available|pinned (true/false)
// The "pinned" flag means the admin froze the version with `choco pin`;
// we return those rows too but callers can filter them out if needed.
func ListUpgrades() ([]Package, error) {
	if !IsInstalled() {
		return nil, nil
	}
	out, code, err := runChoco("outdated", "--limit-output", "--no-color")
	if err != nil {
		return nil, err
	}
	// `choco outdated` returns exit 2 when there are packages to upgrade,
	// exit 0 when everything is current. Only treat other codes as errors.
	if code != 0 && code != 2 {
		return nil, fmt.Errorf("choco outdated exit %d: %s", code, firstLine(out))
	}
	var pkgs []Package
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "chocolatey v") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		id := strings.TrimSpace(parts[0])
		cur := strings.TrimSpace(parts[1])
		avail := strings.TrimSpace(parts[2])
		if id == "" || cur == "" || avail == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:      id,
			ID:        id,
			Version:   cur,
			Available: avail,
			Source:    "chocolatey",
		})
	}
	return pkgs, nil
}

// commonFlags are appended to every install/upgrade/uninstall call.
// --yes        — skip all confirmation prompts
// --no-progress — disable the spinner/progress bar (cleaner in logs)
// --limit-output — where supported, reduces console noise
var commonFlags = []string{"--yes", "--no-progress"}

// RunInstall installs a Chocolatey package. Version is optional; pass
// "" for the latest.
func RunInstall(id, version string) (string, int) {
	args := []string{"install", id}
	if version != "" {
		args = append(args, "--version", version)
	}
	args = append(args, commonFlags...)
	out, code, err := runChoco(args...)
	if err != nil {
		return err.Error(), -1
	}
	return out, code
}

// RunUpgrade upgrades a single Chocolatey package to the latest version.
func RunUpgrade(id string) (string, int) {
	args := append([]string{"upgrade", id}, commonFlags...)
	out, code, err := runChoco(args...)
	if err != nil {
		return err.Error(), -1
	}
	return out, code
}

// RunUpgradeAll upgrades every outdated Chocolatey package.
func RunUpgradeAll() (string, int) {
	args := append([]string{"upgrade", "all"}, commonFlags...)
	out, code, err := runChoco(args...)
	if err != nil {
		return err.Error(), -1
	}
	return out, code
}

// RunUninstall removes a Chocolatey package.
func RunUninstall(id string) (string, int) {
	args := append([]string{"uninstall", id}, commonFlags...)
	out, code, err := runChoco(args...)
	if err != nil {
		return err.Error(), -1
	}
	return out, code
}

// EnsureChoco bootstraps Chocolatey via the official installation script
// if choco.exe isn't already present. Uses the canonical
// https://chocolatey.org/install.ps1 pipeline documented at
// chocolatey.org/install. Returns nil when choco is (now) present, an
// error when the install script itself failed.
//
// Safe to call idempotently on every agent boot — a quick Find() returns
// fast when choco is already there.
func EnsureChoco(logf func(string, ...any)) error {
	if IsInstalled() {
		return nil
	}
	logf("chocolatey not found — bootstrapping via install.ps1")
	script := `
$ErrorActionPreference = 'Stop';
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force;
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = hideWindow()
	// Allow up to 5 minutes for the install — it downloads .NET 4.8 on
	// bare Windows builds that don't already have it.
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start install script: %w", err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("install script failed: %w", err)
		}
	case <-time.After(5 * time.Minute):
		_ = cmd.Process.Kill()
		return fmt.Errorf("install script timed out")
	}
	// Re-probe — the installer adds ChocolateyInstall to PATH but only
	// for new processes. Find() tolerates this because it also checks
	// the well-known path.
	if !IsInstalled() {
		return fmt.Errorf("post-install Find() returned empty")
	}
	logf("chocolatey bootstrap complete")
	return nil
}

// ExitCodeResult maps a chocolatey exit code to a short human label.
// Chocolatey's codes are less systematic than winget's; we cover the
// common ones here and fall back to "exit:<n>" for anything else.
func ExitCodeResult(code int) string {
	switch code {
	case 0:
		return "completed ok"
	case 1:
		return "failed"
	case 2:
		return "unfinished (pending reboot or partial)"
	case 350:
		return "pending reboot"
	case 1641, 3010:
		return "completed; reboot required"
	case -1:
		return "chocolatey not installed"
	}
	return fmt.Sprintf("exit:%d", code)
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return s[:i]
		}
	}
	return s
}

// dirOf is exported for tests that want to know where choco actually
// resolved from. Not used by production code paths.
func dirOf(path string) string { return filepath.Dir(path) }
