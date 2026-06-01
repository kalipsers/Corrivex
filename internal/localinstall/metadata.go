package localinstall

import (
	"path/filepath"
	"regexp"
	"strings"
)

var installerVersionRe = regexp.MustCompile(`(?i)(?:^|[\s._-])v?(\d+\.\d+(?:\.\d+){0,3})`)

// DiscoveredInstaller is one installer found on a configured share.
type DiscoveredInstaller struct {
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	Path          string `json:"path"`
	FrameworkHint string `json:"framework_hint,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Source        string `json:"source,omitempty"`
}

// AnalyzePath extracts conservative product/version metadata from an installer
// filename. Framework detection is filled by the Windows scanner when possible.
func AnalyzePath(path string) DiscoveredInstaller {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	version := ""
	matches := installerVersionRe.FindAllStringSubmatchIndex(stem, -1)
	if len(matches) > 0 {
		m := matches[len(matches)-1]
		version = stem[m[2]:m[3]]
		stem = strings.TrimSpace(stem[:m[0]] + " " + stem[m[1]:])
	}
	name := cleanInstallerName(stem)
	if name == "" {
		name = strings.TrimSuffix(base, ext)
	}
	return DiscoveredInstaller{
		Name:    name,
		Version: version,
		Path:    path,
		Source:  "smb_scan",
	}
}

func cleanInstallerName(s string) string {
	repl := strings.NewReplacer("_", " ", "-", " ", ".", " ")
	s = repl.Replace(s)
	words := strings.Fields(s)
	out := words[:0]
	for _, w := range words {
		lw := strings.ToLower(strings.Trim(w, "()[]{}"))
		switch lw {
		case "setup", "installer", "install", "x64", "x86", "win64", "win32", "windows", "amd64":
			continue
		default:
			out = append(out, w)
		}
	}
	return strings.Join(out, " ")
}

func IsInstallerPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".msi" || ext == ".exe"
}
