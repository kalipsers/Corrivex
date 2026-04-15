// Package regscan reads the Windows uninstall registry trees to find
// installed software that winget does not know about — classic MSI / EXE
// bundlers, vendor tooling, internal installers, older games, etc.
//
// Cross-platform: filters and package types live in the main file;
// regscan_windows.go contains the real Windows registry code;
// regscan_other.go contains a stub so the server cross-compiles.
package regscan

import (
	"regexp"
	"strconv"
	"strings"
)

// Package is the subset of uninstall-registry fields Corrivex records.
// Intentionally parallel to winget.Package so the agent can merge lists
// without a transformation layer.
type Package struct {
	Name      string // DisplayName
	ID        string // registry subkey name (namespace with reg: prefix before sending)
	Version   string // DisplayVersion
	Publisher string // Publisher
}

// Filters controls which registry rows are suppressed. Values map
// one-to-one with `reg_scan_*` settings rows in the DB.
type Filters struct {
	SkipMSPublisher       bool
	SkipKBUpdates         bool
	SkipRedistributables  bool
	SkipSystemComponents  bool
	SkipGUIDNames         bool
	MinNameLength         int
	CustomSkipPatterns    []*regexp.Regexp // each line from reg_scan_custom_skip_patterns
	CustomSkipPublishers  map[string]bool  // each line from reg_scan_custom_skip_publishers
}

// DefaultFilters returns sane defaults matching the spec. Admins can
// override any of them via the Settings → Registry scan filters card.
func DefaultFilters() Filters {
	return Filters{
		SkipMSPublisher:      false,
		SkipKBUpdates:        true,
		SkipRedistributables: true,
		SkipSystemComponents: true,
		SkipGUIDNames:        true,
		MinNameLength:        3,
	}
}

// FiltersFromSettings builds a Filters from the raw string map stored in
// the DB's `settings` table. Missing keys fall back to DefaultFilters.
// Values are the string-encoded forms used everywhere else in Corrivex
// ("true"/"false", integers, newline-separated lists).
func FiltersFromSettings(s map[string]string) Filters {
	f := DefaultFilters()
	if v, ok := s["reg_scan_skip_ms_publisher"]; ok {
		f.SkipMSPublisher = truthy(v)
	}
	if v, ok := s["reg_scan_skip_kb_updates"]; ok {
		f.SkipKBUpdates = truthy(v)
	}
	if v, ok := s["reg_scan_skip_redistributables"]; ok {
		f.SkipRedistributables = truthy(v)
	}
	if v, ok := s["reg_scan_skip_system_components"]; ok {
		f.SkipSystemComponents = truthy(v)
	}
	if v, ok := s["reg_scan_skip_guid_names"]; ok {
		f.SkipGUIDNames = truthy(v)
	}
	if v, ok := s["reg_scan_min_name_length"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			f.MinNameLength = n
		}
	}
	f.CustomSkipPatterns = compileRegexLines(s["reg_scan_custom_skip_patterns"])
	f.CustomSkipPublishers = publisherSet(s["reg_scan_custom_skip_publishers"])
	return f
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func compileRegexLines(raw string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, err := regexp.Compile("(?i)" + line)
		if err == nil {
			out = append(out, re)
		}
	}
	return out
}

func publisherSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(line)] = true
	}
	return out
}

// guidRe matches names that are a single GUID in braces, e.g.
// "{12345678-1234-1234-1234-123456789012}". These are usually MSI
// components exposed by the uninstall key but have no meaningful
// DisplayName the user would recognise.
var guidRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// kbRe matches Windows Update KB-number rollups. These clutter the
// software inventory — "Security Update for Microsoft .NET Framework
// (KB5041942)" etc.
var kbRe = regexp.MustCompile(`\b[Kk][Bb]\d{6,8}\b`)

// redistRe matches Microsoft's VC++ / .NET redistributables. Opt-in
// (on by default) — admins who want to audit runtimes can turn this
// filter off.
var redistRe = regexp.MustCompile(`(?i)(Visual C\+\+.*Redistributable|\.NET\b.*(Runtime|Redistributable|Framework)|MSVC|Microsoft Windows Desktop Runtime|Microsoft Windows SDK)`)

// Keep is the filter predicate. Returns true if the registry entry
// should be included in the reported inventory.
func (f Filters) Keep(p Package, systemComponent bool, releaseType string) bool {
	name := strings.TrimSpace(p.Name)
	if len(name) < f.MinNameLength {
		return false
	}
	if f.SkipSystemComponents && systemComponent {
		return false
	}
	if f.SkipGUIDNames && guidRe.MatchString(name) {
		return false
	}
	if f.SkipKBUpdates && kbRe.MatchString(name) {
		return false
	}
	// ReleaseType-based skip
	rt := strings.ToLower(strings.TrimSpace(releaseType))
	if f.SkipKBUpdates && (rt == "update" || rt == "hotfix" || rt == "security update") {
		return false
	}
	if f.SkipRedistributables && redistRe.MatchString(name) {
		return false
	}
	pub := strings.TrimSpace(p.Publisher)
	if f.SkipMSPublisher {
		pl := strings.ToLower(pub)
		if pl == "microsoft corporation" || pl == "microsoft windows" {
			return false
		}
	}
	if len(f.CustomSkipPublishers) > 0 {
		if f.CustomSkipPublishers[strings.ToLower(pub)] {
			return false
		}
	}
	for _, re := range f.CustomSkipPatterns {
		if re.MatchString(name) {
			return false
		}
	}
	return true
}

// SanitizeID produces the `package_id` that goes into the server's
// installed_software row for a registry entry. Subkey names are almost
// always either a GUID or a Vendor.Product string; we prefix with
// `reg:` so registry-sourced rows never collide with winget IDs.
func SanitizeID(subkey, name string) string {
	s := strings.TrimSpace(subkey)
	if s == "" {
		s = strings.TrimSpace(name)
	}
	// Collapse whitespace and keep it short — the column is VARCHAR(255).
	s = strings.Join(strings.Fields(s), "_")
	if len(s) > 200 {
		s = s[:200]
	}
	return "reg:" + s
}
