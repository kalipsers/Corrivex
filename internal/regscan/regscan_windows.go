//go:build windows

package regscan

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// roots lists every uninstall-tree the scanner walks. Missing keys are
// tolerated (not every host has a Wow6432Node tree, for example).
var roots = []struct {
	Key  registry.Key
	Path string
	Desc string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "hklm"},
	{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "hklm-wow"},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "hkcu"},
}

// ListInstalled walks every uninstall tree and returns the rows that
// pass the filter. Filter nil ⇒ DefaultFilters.
func ListInstalled(filt *Filters) ([]Package, error) {
	f := DefaultFilters()
	if filt != nil {
		f = *filt
	}
	// Dedupe across the three roots (some apps register under both HKLM
	// and HKCU, especially with per-user installers).
	seen := map[string]bool{}
	var out []Package

	for _, r := range roots {
		key, err := registry.OpenKey(r.Key, r.Path, registry.ENUMERATE_SUB_KEYS|registry.READ)
		if err != nil {
			// Root missing / no access — skip it, keep the others.
			continue
		}
		subkeys, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err != nil {
			continue
		}
		for _, sk := range subkeys {
			p, sys, rt, ok := readUninstallEntry(r.Key, r.Path+`\`+sk)
			if !ok {
				continue
			}
			if !f.Keep(p, sys, rt) {
				continue
			}
			p.ID = SanitizeID(sk, p.Name)
			dk := strings.ToLower(p.Name + "\x00" + p.Version)
			if seen[dk] {
				continue
			}
			seen[dk] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// readUninstallEntry reads one uninstall subkey. Returns the package,
// whether SystemComponent=1 is set, the ReleaseType string, and an ok
// flag (false if the entry has no DisplayName — those rows are
// unnamed MSI metadata that's useless in a report).
func readUninstallEntry(root registry.Key, path string) (Package, bool, string, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return Package{}, false, "", false
	}
	defer k.Close()

	name, _, _ := k.GetStringValue("DisplayName")
	if strings.TrimSpace(name) == "" {
		return Package{}, false, "", false
	}
	version, _, _ := k.GetStringValue("DisplayVersion")
	publisher, _, _ := k.GetStringValue("Publisher")
	releaseType, _, _ := k.GetStringValue("ReleaseType")

	var systemComponent bool
	if v, _, err := k.GetIntegerValue("SystemComponent"); err == nil && v == 1 {
		systemComponent = true
	}

	return Package{
		Name:      strings.TrimSpace(name),
		Version:   strings.TrimSpace(version),
		Publisher: strings.TrimSpace(publisher),
	}, systemComponent, releaseType, true
}
