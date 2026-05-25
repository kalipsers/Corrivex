//go:build windows

package winget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCmd(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-winget.cmd")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(body, "\n", "\r\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunWingetMonitoredStreamsStdoutAndStderr(t *testing.T) {
	cmd := writeCmd(t, `@echo off
echo first line
echo second line 1>&2
exit /b 0
`)
	var logs []string
	out, code := runWingetMonitored(context.Background(), cmd, nil, 5*time.Second, 100*time.Millisecond, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})

	if code != 0 {
		t.Fatalf("code=%d output=%q", code, out)
	}
	if !strings.Contains(out, "first line") || !strings.Contains(out, "second line") {
		t.Fatalf("output did not capture stdout+stderr: %q", out)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "first line") || !strings.Contains(joined, "second line") {
		t.Fatalf("logs=%#v", logs)
	}
}

func TestRunWingetMonitoredKillsTimedOutProcess(t *testing.T) {
	cmd := writeCmd(t, `@echo off
echo begin
ping -n 6 127.0.0.1 >nul
echo late
exit /b 0
`)
	var logs []string
	start := time.Now()
	out, code := runWingetMonitored(context.Background(), cmd, nil, 200*time.Millisecond, 50*time.Millisecond, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})

	if got := ExitCodeResult(code); got != "timeout_killed" {
		t.Fatalf("ExitCodeResult(%d)=%q output=%q", code, got, out)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout did not kill promptly; elapsed=%s", time.Since(start))
	}
	if !strings.Contains(out, "begin") || strings.Contains(out, "late") {
		t.Fatalf("unexpected output after timeout: %q", out)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "still running") {
		t.Fatalf("expected idle heartbeat log, got %#v", logs)
	}
}

func TestRunWingetMonitoredCapsStoredOutput(t *testing.T) {
	cmd := writeCmd(t, `@echo off
for /L %%i in (1,1,3000) do echo line %%i abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz
exit /b 0
`)
	out, code := runWingetMonitored(context.Background(), cmd, nil, 5*time.Second, time.Second, nil)

	if code != 0 {
		t.Fatalf("code=%d output head=%q", code, out[:min(len(out), 120)])
	}
	if len(out) > maxWingetOutputBytes+512 {
		t.Fatalf("output was not capped: len=%d max=%d", len(out), maxWingetOutputBytes)
	}
	if !strings.Contains(out, "output truncated") {
		t.Fatalf("expected truncation marker in output")
	}
}
