//go:build windows

package localinstall

import (
	"io/fs"
	"path/filepath"
	"strings"
)

type ScanOptions struct {
	MaxDepth int
	MaxFiles int
}

// ScanDirectory walks a share/local directory and returns MSI/EXE installers
// with best-effort framework and filename metadata.
func ScanDirectory(root string, opts ScanOptions) ([]DiscoveredInstaller, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 4
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 200
	}
	root = filepath.Clean(root)
	rootDepth := pathDepth(root)
	var out []DiscoveredInstaller
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path != root && d.IsDir() {
			name := strings.ToLower(d.Name())
			if name == "$recycle.bin" || name == "system volume information" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			if pathDepth(path)-rootDepth > opts.MaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !IsInstallerPath(path) {
			return nil
		}
		item := AnalyzePath(path)
		if det, derr := Detect(path); derr == nil {
			item.FrameworkHint = string(det.Framework)
			item.Reason = det.Reason
		}
		out = append(out, item)
		if len(out) >= opts.MaxFiles {
			return fs.SkipAll
		}
		return nil
	})
	return out, err
}

func pathDepth(path string) int {
	path = filepath.Clean(path)
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' })
	return len(parts)
}
