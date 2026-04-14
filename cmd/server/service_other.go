//go:build !windows

package main

// maybeRunAsService is Windows-only. On other platforms it is a no-op so the
// caller falls through to a normal foreground run.
func maybeRunAsService(_ ServerOptions) bool { return false }

// The install/uninstall/control entry-points are referenced from main.go but
// are guarded by `runtime.GOOS == "windows"`, so they should never be called
// here. Provide stubs so the file compiles on linux.
func runWindowsInstall()              {}
func runWindowsUninstall()            {}
func runWindowsCtl(action string)     {}
func runWindowsStatus()               {}
