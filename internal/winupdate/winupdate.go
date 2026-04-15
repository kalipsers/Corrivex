//go:build windows

// Package winupdate drives the built-in Windows Update system via the
// Microsoft.Update.Session COM object. It purposely avoids adding any
// PowerShell module dependency (PSWindowsUpdate etc.) so it works out of the
// box on every supported Windows version.
package winupdate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Update mirrors the fields the dashboard cares about.
type Update struct {
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	KB             []string `json:"kb"`
	Size           int64    `json:"size"`
	Severity       string   `json:"severity"`
	IsDownloaded   bool     `json:"is_downloaded"`
	RebootRequired bool     `json:"reboot_required"`
	UpdateID       string   `json:"update_id"`
	Categories     []string `json:"categories"`
}

// List returns pending (IsInstalled=0) software updates.
// The COM search can take 30 s – 2 min on first run; the caller should apply
// a context timeout (2 min is a reasonable default).
func List(ctx context.Context) ([]Update, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", listScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("search failed: %w; output=%s", err, buf.String())
	}
	data := strings.TrimSpace(buf.String())
	if data == "" || data == "null" {
		return nil, nil
	}
	// ConvertTo-Json emits a single object when only one update exists. Wrap.
	if !strings.HasPrefix(data, "[") {
		data = "[" + data + "]"
	}
	var out []Update
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		sample := data
		if len(sample) > 200 {
			sample = sample[:200]
		}
		return nil, fmt.Errorf("parse: %w; sample=%s", err, sample)
	}
	return out, nil
}

// InstallAll downloads and installs every pending software update. The
// callback receives progress lines suitable for the agent's live log feed.
func InstallAll(ctx context.Context, logf func(format string, args ...any)) (string, int) {
	return runPSStreaming(ctx, installAllScript, logf, 60*time.Minute)
}

var validUpdateID = regexp.MustCompile(`^[0-9a-fA-F\-]+$`)

// InstallByID targets a single update identified by UpdateID (GUID-like).
func InstallByID(ctx context.Context, updateID string, logf func(format string, args ...any)) (string, int) {
	if !validUpdateID.MatchString(updateID) || len(updateID) > 64 {
		return "invalid update id", -1
	}
	script := strings.ReplaceAll(installByIDScript, "__ID__", updateID)
	return runPSStreaming(ctx, script, logf, 60*time.Minute)
}

// runPSStreaming executes a PowerShell script, streaming stdout/stderr lines
// to logf. Returns the concatenated final-line summary and the exit code.
func runPSStreaming(ctx context.Context, script string, logf func(string, ...any), timeout time.Duration) (string, int) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err.Error(), -1
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err.Error(), -1
	}
	var lastLine string
	var allOutput strings.Builder
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(io.Reader(stdout))
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line == "" {
				continue
			}
			lastLine = line
			allOutput.WriteString(line)
			allOutput.WriteByte('\n')
			logf("wu: %s", line)
		}
		close(done)
	}()
	err = cmd.Wait()
	<-done
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return allOutput.String(), -1
		}
	}
	if lastLine == "" {
		lastLine = "exit:" + fmt.Sprint(code)
	}
	return lastLine, code
}

// -- PowerShell scripts ----------------------------------------------------

const listScript = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding          = [System.Text.Encoding]::UTF8
try {
    $s = New-Object -ComObject Microsoft.Update.Session
    $s.ClientApplicationID = 'Corrivex'
    $srch = $s.CreateUpdateSearcher()
    $r = $srch.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $out = @()
    foreach ($u in $r.Updates) {
        $cats = @()
        foreach ($c in $u.Categories) { $cats += [string]$c.Name }
        $kbs = @()
        foreach ($k in $u.KBArticleIDs) { $kbs += [string]$k }
        # MinDownloadSize is the size that will actually transfer for the
        # applicable variant of this update — matches what Settings → Update
        # shows. MaxDownloadSize is the bundle worst-case (sum of all
        # variants), which can be tens of GB for cumulative updates and is
        # almost never what the user downloads. Prefer Min, fall back to Max.
        $minSize = [long]$u.MinDownloadSize
        $maxSize = [long]$u.MaxDownloadSize
        $size    = if ($minSize -gt 0) { $minSize } else { $maxSize }
        $out += [PSCustomObject]@{
            title           = [string]$u.Title
            description     = [string]$u.Description
            kb              = $kbs
            size            = $size
            severity        = [string]$u.MsrcSeverity
            is_downloaded   = [bool]$u.IsDownloaded
            reboot_required = [bool]$u.RebootRequired
            update_id       = [string]$u.Identity.UpdateID
            categories      = $cats
        }
    }
    $out | ConvertTo-Json -Depth 4 -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`

const installAllScript = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding          = [System.Text.Encoding]::UTF8
try {
    $s = New-Object -ComObject Microsoft.Update.Session
    $s.ClientApplicationID = 'Corrivex'
    $srch = $s.CreateUpdateSearcher()
    $r = $srch.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    if ($r.Updates.Count -eq 0) { Write-Output 'no pending updates'; exit 0 }

    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $r.Updates) {
        if ($u.EulaAccepted -eq $false) { try { $u.AcceptEula() } catch {} }
        [void]$coll.Add($u)
    }
    Write-Output ('downloading ' + $coll.Count + ' update(s)')
    $dl = $s.CreateUpdateDownloader()
    $dl.Updates = $coll
    $null = $dl.Download()
    Write-Output 'installing...'
    $ins = $s.CreateUpdateInstaller()
    $ins.Updates = $coll
    $res = $ins.Install()
    Write-Output ('result_code=' + $res.ResultCode + ' reboot=' + $res.RebootRequired)
    if ($res.RebootRequired) { exit 3010 }
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`

const installByIDScript = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding          = [System.Text.Encoding]::UTF8
try {
    $id = '__ID__'
    $s = New-Object -ComObject Microsoft.Update.Session
    $s.ClientApplicationID = 'Corrivex'
    $srch = $s.CreateUpdateSearcher()
    $r = $srch.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $target = $null
    foreach ($u in $r.Updates) { if ($u.Identity.UpdateID -eq $id) { $target = $u; break } }
    if (-not $target) { Write-Output 'not_found'; exit 1 }

    Write-Output ('target: ' + $target.Title)
    if ($target.EulaAccepted -eq $false) { try { $target.AcceptEula() } catch {} }
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    [void]$coll.Add($target)

    Write-Output 'downloading...'
    $dl = $s.CreateUpdateDownloader()
    $dl.Updates = $coll
    $null = $dl.Download()

    Write-Output 'installing...'
    $ins = $s.CreateUpdateInstaller()
    $ins.Updates = $coll
    $res = $ins.Install()
    Write-Output ('result_code=' + $res.ResultCode + ' reboot=' + $res.RebootRequired)
    if ($res.RebootRequired) { exit 3010 }
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
`
