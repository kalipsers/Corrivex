//go:build windows

package agent

import (
	"strings"

	"github.com/markov/corrivex/internal/regscan"
	"github.com/markov/corrivex/internal/winget"
)

// mergeRegistry supplements the winget inventory with entries from the
// Windows uninstall registry trees. winget stays authoritative for apps
// it knows about; registry entries that fuzzy-match a winget row flip
// that row's Source column to "both" so the UI can show the agreement.
// Unmatched registry entries are appended with Source = "registry" and a
// `reg:` prefix on their ID (see regscan.SanitizeID).
//
// `logf` is the agent's WebSocket-backed log stream — used for one-line
// visibility into how many rows came from each source.
func mergeRegistry(winList []winget.Package, logf func(format string, a ...any)) []winget.Package {
	// Set the default source on every winget row so the merge below can
	// promote it to "both" cleanly.
	for i := range winList {
		if winList[i].Source == "" {
			winList[i].Source = "winget"
		}
	}

	regList, err := regscan.ListInstalled(nil)
	if err != nil {
		logf("registry scan failed: %v", err)
		return winList
	}
	if len(regList) == 0 {
		return winList
	}

	// Index the winget entries by normalised DisplayName for O(1) match.
	wingetByName := make(map[string]int, len(winList))
	for i, p := range winList {
		wingetByName[normalise(p.Name)] = i
	}

	added := 0
	promoted := 0
	for _, r := range regList {
		key := normalise(r.Name)
		if idx, ok := wingetByName[key]; ok {
			if winList[idx].Source != "both" {
				winList[idx].Source = "both"
				promoted++
			}
			continue
		}
		winList = append(winList, winget.Package{
			ID:      r.ID,
			Name:    r.Name,
			Version: r.Version,
			Source:  "registry",
		})
		added++
	}
	if added > 0 || promoted > 0 {
		logf("registry merge: +%d new, %d confirmed (winget+registry)", added, promoted)
	}
	return winList
}

// normalise lowercases, trims, and strips common separators so e.g.
// "Mozilla Firefox (64-bit)" and "Mozilla Firefox" collapse to the
// same key. Conservative — misses still exist (different vendor
// renamings), but false-positive rate stays low because we also
// compare the whole normalised string, not a substring.
func normalise(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// Drop common suffix noise.
	for _, tail := range []string{
		" (64-bit)", " (32-bit)", " (x64)", " (x86)",
		" 64-bit", " 32-bit",
	} {
		s = strings.TrimSuffix(s, tail)
	}
	// Collapse whitespace.
	s = strings.Join(strings.Fields(s), " ")
	return s
}
