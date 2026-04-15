//go:build windows

// Package winget shells out to the winget.exe command.
package winget

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Package describes a pending winget upgrade.
type Package struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Available string `json:"available"`
	Source    string `json:"source"`
}

// Find the winget.exe path. Returns empty if not found.
func Find() string {
	if p, err := exec.LookPath("winget.exe"); err == nil {
		return p
	}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		matches, _ := filepath.Glob(filepath.Join(pf, `WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe`))
		if len(matches) > 0 {
			return matches[len(matches)-1]
		}
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		p := filepath.Join(local, `Microsoft\WindowsApps\winget.exe`)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ExitCodeResult maps a winget exit code to a human-readable slug. Unknown
// negative codes (winget-specific HRESULTs under the 0x8A15xxxx range) are
// rendered in hex so admins can look them up at
// https://learn.microsoft.com/en-us/windows/package-manager/winget/returnCodes.
func ExitCodeResult(code int) string {
	switch code {
	// MSI / Windows installer returns
	case 0:
		return "completed"
	case 3010:
		return "completed_reboot_required"
	case 1641:
		return "completed_reboot_initiated"
	case 1618:
		return "another_install_running"

	// winget-specific HRESULTs (0x8A15xxxx range, sign-extended int32 form)
	case -1978335231: // 0x8A150001
		return "internal_error"
	case -1978335230: // 0x8A150002
		return "invalid_arguments"
	case -1978335229: // 0x8A150003
		return "command_failed"
	case -1978335224: // 0x8A150008
		return "download_failed"
	case -1978335215: // 0x8A150011 — hash mismatch
		return "installer_hash_mismatch"
	case -1978335212: // 0x8A150014
		return "no_applications_found"
	case -1978335205: // 0x8A15001B
		return "msstore_blocked_by_policy"
	case -1978335193: // 0x8A150027
		return "operation_canceled"
	case -1978335188: // 0x8A15002C
		return "package_already_installed"
	case -1978335186: // 0x8A15002E
		return "installer_not_applicable"
	case -1978335183: // 0x8A150031 — sometimes emitted as "installer running"
		return "installer_already_running"
	case -1978335181: // 0x8A150033
		return "update_not_applicable"
	case -1978335180: // 0x8A150034
		return "update_all_has_failure"
	case -1978335179: // 0x8A150035
		return "install_failed"
	case -1978335177: // 0x8A150037
		return "dependency_not_found"
	case -1978335140: // 0x8A150060
		return "install_in_progress"
	case -1978335085: // 0x8A150097
		return "package_not_found"
	case -1978334972: // 0x8A150108
		return "reboot_required"
	case -1978334959: // 0x8A150111
		return "package_agreements_not_accepted"

	default:
		// Unknown: if it's in the winget range, show hex so admins can
		// cross-reference Microsoft's returnCodes doc directly.
		if code < 0 {
			return fmt.Sprintf("exit:0x%08X", uint32(code))
		}
		return fmt.Sprintf("exit:%d", code)
	}
}

// ListUpgrades runs `winget upgrade` and parses the table.
func ListUpgrades() ([]Package, error) {
	wg := Find()
	if wg == "" {
		return nil, fmt.Errorf("winget not found")
	}
	out, err := runWinget(wg, "upgrade", "--accept-source-agreements", "--include-unknown")
	// exit code can be non-zero with valid data — parse regardless
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return parseUpgradeTable(out), nil
}

// ListInstalled runs `winget list` and returns every package that has both
// a usable Id and a version. Used to populate the per-host installed-
// software inventory + diff-driven version history on the server.
//
// Skips Windows Add-Remove-Programs entries that don't carry a
// `Vendor.Product`-style identifier (their IDs use backslashes which the
// shared parser ignores) — those aren't actionable from winget anyway.
func ListInstalled() ([]Package, error) {
	wg := Find()
	if wg == "" {
		return nil, fmt.Errorf("winget not found")
	}
	out, err := runWinget(wg, "list", "--accept-source-agreements")
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return parseListTable(out), nil
}

// RunUpgradeAll runs `winget upgrade --all --silent`.
func RunUpgradeAll() (string, int) {
	wg := Find()
	if wg == "" {
		return "winget not found", -1
	}
	out, code := runWinget2(wg, "upgrade", "--all", "--silent", "--include-unknown", "--accept-source-agreements", "--accept-package-agreements")
	return out, code
}

// RunUpgradeID upgrades one package.
func RunUpgradeID(id string) (string, int) {
	wg := Find()
	if wg == "" {
		return "winget not found", -1
	}
	out, code := runWinget2(wg, "upgrade", "--id", id, "--silent", "--accept-source-agreements", "--accept-package-agreements")
	return out, code
}

// RunInstall installs a package (optional version).
func RunInstall(id, version string) (string, int) {
	wg := Find()
	if wg == "" {
		return "winget not found", -1
	}
	args := []string{"install", "--id", id, "--silent", "--accept-source-agreements", "--accept-package-agreements"}
	if version != "" {
		args = append(args, "--version", version)
	}
	return runWinget2(wg, args...)
}

// RunUninstall uninstalls a package.
func RunUninstall(id string) (string, int) {
	wg := Find()
	if wg == "" {
		return "winget not found", -1
	}
	return runWinget2(wg, "uninstall", "--id", id, "--silent", "--accept-source-agreements")
}

// EnsureInstalled returns the path to winget.exe. If winget isn't present
// it tries — in order — to re-register an already-deployed AppX package,
// then to download the latest release from GitHub (with Visual C++ Libs and
// Microsoft UI.Xaml dependencies) and install it for all users.
//
// Output of the PowerShell installer is fed to logf line-by-line so the
// progress streams live to the dashboard.
func EnsureInstalled(logf func(format string, args ...any)) (string, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if p := Find(); p != "" {
		logf("winget found at %s", p)
		return p, nil
	}
	logf("winget not found, attempting to install (this may take a minute)...")

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", wingetInstallScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout // fold stderr into the same pipe

	if err := cmd.Start(); err != nil {
		return "", err
	}

	// Stream output line-by-line so the dashboard shows live progress.
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line == "" {
				continue
			}
			logf("winget-install: %s", line)
		}
		close(done)
	}()

	// Cap at 15 minutes in case the installer hangs on a flaky network.
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case err := <-waitErr:
		<-done
		if err != nil {
			return "", fmt.Errorf("installer exited: %w", err)
		}
	case <-time.After(15 * time.Minute):
		cmd.Process.Kill()
		return "", fmt.Errorf("installer timed out")
	}

	if p := Find(); p != "" {
		logf("winget installed at %s", p)
		return p, nil
	}
	return "", fmt.Errorf("winget still not available after install script")
}

// wingetInstallScript is a self-contained PowerShell program that brings a
// working winget onto the box. It is small, dependency-free, and tolerant of
// partial progress — each stage is isolated so one failed mechanism doesn't
// stop the next from running.
const wingetInstallScript = `
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding          = [System.Text.Encoding]::UTF8

function Has-Winget {
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) { return $true }
    $candidate = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1
    return [bool]$candidate
}

if (Has-Winget) { Write-Output 'already present'; exit 0 }

# --- Strategy 1: re-register an existing AppX package --------------------
Write-Output 'stage 1: re-register existing AppX...'
try {
    $pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pkg) {
        Add-AppxPackage -DisableDevelopmentMode -Register "$($pkg.InstallLocation)\AppXManifest.xml" -ErrorAction Stop
        Write-Output "  registered $($pkg.PackageFullName)"
    } else {
        Write-Output '  no existing package found'
    }
} catch {
    Write-Output "  re-register failed: $_"
}
if (Has-Winget) { Write-Output 'winget ready'; exit 0 }

# --- Strategy 2: download the latest release + deps from GitHub ----------
Write-Output 'stage 2: download latest release...'
$temp = Join-Path $env:TEMP ('corrivex-winget-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    Write-Output '  fetching VC++ libs'
    Invoke-WebRequest 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile "$temp\vclibs.appx" -UseBasicParsing

    Write-Output '  fetching UI.Xaml 2.8'
    Invoke-WebRequest 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx' -OutFile "$temp\xaml.appx" -UseBasicParsing

    Write-Output '  querying latest winget release'
    $release = Invoke-RestMethod 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' -UseBasicParsing -Headers @{ 'User-Agent' = 'Corrivex' }
    $msix    = $release.assets | Where-Object { $_.name -like '*.msixbundle' }   | Select-Object -First 1
    $license = $release.assets | Where-Object { $_.name -like '*License*.xml' } | Select-Object -First 1
    if (-not $msix) { throw 'no .msixbundle asset found on latest release' }

    Write-Output "  downloading $($msix.name) ($([math]::Round($msix.size/1MB,1)) MB)"
    Invoke-WebRequest $msix.browser_download_url -OutFile "$temp\winget.msixbundle" -UseBasicParsing
    if ($license) {
        Invoke-WebRequest $license.browser_download_url -OutFile "$temp\license.xml" -UseBasicParsing
    }

    Write-Output '  installing dependencies'
    Add-AppxPackage -Path "$temp\vclibs.appx" -ErrorAction SilentlyContinue
    Add-AppxPackage -Path "$temp\xaml.appx"   -ErrorAction SilentlyContinue

    if ($license) {
        Write-Output '  installing winget (Add-AppxProvisionedPackage)'
        $dep = @("$temp\vclibs.appx","$temp\xaml.appx")
        Add-AppxProvisionedPackage -Online -PackagePath "$temp\winget.msixbundle" -LicensePath "$temp\license.xml" -DependencyPackagePath $dep -ErrorAction SilentlyContinue | Out-Null
    } else {
        Write-Output '  installing winget (Add-AppxPackage)'
        Add-AppxPackage -Path "$temp\winget.msixbundle" -DependencyPath @("$temp\vclibs.appx","$temp\xaml.appx") -ErrorAction SilentlyContinue
    }
} catch {
    Write-Output "  download/install error: $_"
} finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}

if (Has-Winget) { Write-Output 'winget ready'; exit 0 }

Write-Output 'winget could not be installed automatically on this host'
exit 1
`

// -- internals --------------------------------------------------------------

func runWinget(wg string, args ...string) (string, error) {
	cmd := exec.Command(wg, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func runWinget2(wg string, args ...string) (string, int) {
	cmd := exec.Command(wg, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Windows returns HRESULT-style exit codes as uint32; Go's
			// ExitCode() keeps the high bit, so a winget "package not found"
			// (0x8A150097 → int32 -1978335085) arrives here as 2316632211.
			// Fold it back to the signed int32 form that matches
			// Microsoft's documented constants.
			code = int(int32(exitErr.ExitCode()))
		} else {
			return err.Error(), -1
		}
	}
	return string(b), code
}

// parseListTable extracts (name, id, version, source) tuples from a
// `winget list` output. Same column-aware approach as parseUpgradeTable —
// the only difference is the absence of the "Available" column.
func parseListTable(out string) []Package {
	var pkgs []Package
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	sepIdx := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), strings.Repeat("-", 10)) {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 {
		return pkgs
	}
	for i := sepIdx + 1; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], " \t")
		if l == "" {
			continue
		}
		// Footer counters / pagination hints we should ignore.
		ll := strings.ToLower(l)
		if strings.Contains(ll, "package(s)") || strings.Contains(ll, "upgrades available") {
			continue
		}
		m := idPattern.FindStringSubmatchIndex(l)
		if m == nil {
			continue
		}
		id := l[m[2]:m[3]]
		name := strings.TrimSpace(l[:m[2]])
		rest := strings.Fields(l[m[3]:])
		var ver, src string
		if len(rest) > 0 {
			ver = rest[0]
		}
		if len(rest) > 1 {
			src = rest[1]
		}
		if src == "" {
			src = "winget"
		}
		if ver == "" || ver == "?" {
			continue
		}
		pkgs = append(pkgs, Package{Name: name, ID: id, Version: ver, Source: src})
	}
	return pkgs
}

// parseUpgradeTable extracts packages from winget's fixed-width text output.
// Matches the id pattern like Microsoft.Edge, Google.Chrome, etc.
var idPattern = regexp.MustCompile(`\s+([A-Za-z][\w+\-]*\.[A-Za-z][\w+\-\.]*)\s{2,}`)

func parseUpgradeTable(out string) []Package {
	var pkgs []Package
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")

	// Find header separator (dashes)
	sepIdx := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), strings.Repeat("-", 10)) {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 {
		return pkgs
	}

	for i := sepIdx + 1; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], " \t")
		if l == "" {
			continue
		}
		if strings.Contains(strings.ToLower(l), "upgrades available") {
			break
		}
		m := idPattern.FindStringSubmatchIndex(l)
		if m == nil {
			continue
		}
		id := l[m[2]:m[3]]
		name := strings.TrimSpace(l[:m[2]])
		rest := strings.Fields(l[m[3]:])
		// rest: [version, available, source]
		var ver, avail, src string
		if len(rest) > 0 {
			ver = rest[0]
		}
		if len(rest) > 1 {
			avail = rest[1]
		}
		if len(rest) > 2 {
			src = rest[2]
		} else {
			src = "winget"
		}
		pkgs = append(pkgs, Package{Name: name, ID: id, Version: ver, Available: avail, Source: src})
	}
	return pkgs
}
