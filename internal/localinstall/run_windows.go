//go:build windows

package localinstall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// RunOptions carries the agent-facing knobs for a single install call.
type RunOptions struct {
	Path          string   // file path or UNC path to the installer
	OverrideArgs  []string // non-nil replaces DefaultSilentArgs entirely
	ExpectedCodes []int    // exit codes treated as success (default [0, 3010])
	Framework     Framework // hint from the admin; empty = auto-detect
}

// Result is the outcome of one install call.
type Result struct {
	ExitCode  int
	Output    string
	Framework Framework
	SilentArg []string
	Success   bool
}

// Run executes the installer at opts.Path silently. If the admin has
// not forced a framework or args via opts, Detect is called first to
// pick the right silent flag.
func Run(ctx context.Context, opts RunOptions) (Result, error) {
	fw := opts.Framework
	silent := opts.OverrideArgs
	reason := "admin override"
	if fw == "" {
		d, err := Detect(opts.Path)
		if err != nil {
			return Result{}, err
		}
		fw = d.Framework
		reason = d.Reason
		if silent == nil {
			silent = d.SilentArgs
		}
	}
	if silent == nil {
		silent = DefaultSilentArgs(fw)
	}
	if silent == nil {
		return Result{
			Framework: fw,
			Output:    "no silent-install flags known for framework " + string(fw) + " (" + reason + "); provide silent_args_override",
			ExitCode:  -1,
		}, nil
	}

	var cmd *exec.Cmd
	switch fw {
	case FrameworkMSI, FrameworkAdvancedInstaller:
		// msiexec is the program; installer path goes in as /i <path>.
		args := append([]string{"/i", opts.Path}, silent...)
		cmd = exec.CommandContext(ctx, "msiexec", args...)
	default:
		// .exe installers: the file itself is the program.
		cmd = exec.CommandContext(ctx, opts.Path, silent...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ex, ok := err.(*exec.ExitError); ok {
			code = ex.ExitCode()
		} else {
			return Result{Framework: fw, SilentArg: silent, ExitCode: -1, Output: err.Error()}, err
		}
	}

	// expected exit codes → 0 and 3010 (reboot-required) count as success
	// by default; the per-installer row can override this list.
	ok := false
	expected := opts.ExpectedCodes
	if len(expected) == 0 {
		expected = []int{0, 3010}
	}
	for _, e := range expected {
		if code == e {
			ok = true
			break
		}
	}
	return Result{
		ExitCode:  code,
		Output:    string(out),
		Framework: fw,
		SilentArg: silent,
		Success:   ok,
	}, nil
}

// ExitCodeLabel translates MSI and common EXE installer exit codes to
// a short human label for dashboard display.
func ExitCodeLabel(code int) string {
	switch code {
	case 0:
		return "installed"
	case 1602:
		return "user cancelled"
	case 1603:
		return "fatal msi error"
	case 1618:
		return "another install in progress"
	case 1641:
		return "reboot initiated"
	case 3010:
		return "reboot required"
	case -1:
		return "launch failed"
	}
	return fmt.Sprintf("exit:%d", code)
}

// Stringer-ish helper so log lines render cleanly.
func (r Result) String() string {
	head := strings.SplitN(r.Output, "\n", 2)[0]
	return fmt.Sprintf("framework=%s exit=%d (%s) head=%q", r.Framework, r.ExitCode, ExitCodeLabel(r.ExitCode), head)
}
