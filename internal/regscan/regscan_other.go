//go:build !windows

// Stub for non-Windows platforms. Lets the Corrivex server cross-compile
// on Linux (where the agent binary that uses this package is not built
// anyway). Returns an empty list so code paths that try to scan still
// work without special-casing the OS.
package regscan

// ListInstalled always returns nil, nil on non-Windows platforms.
func ListInstalled(filt *Filters) ([]Package, error) { return nil, nil }
