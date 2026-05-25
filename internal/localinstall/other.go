//go:build !windows

// Stub so cmd/server cross-compiles on Linux. The Windows agent is
// the only call site for Run/Detect; this file just keeps Go's type
// checker happy.
package localinstall

import (
	"context"
	"errors"
)

type RunOptions struct {
	Path          string
	OverrideArgs  []string
	ExpectedCodes []int
	Framework     Framework
}

type Result struct {
	ExitCode  int
	Output    string
	Framework Framework
	SilentArg []string
	Success   bool
}

func Detect(path string) (Detection, error) {
	return Detection{Framework: FrameworkUnknown}, nil
}
func Run(ctx context.Context, opts RunOptions) (Result, error) {
	return Result{}, errors.New("localinstall: Windows-only")
}
func ExitCodeLabel(code int) string { return "" }
func (r Result) String() string     { return "" }
