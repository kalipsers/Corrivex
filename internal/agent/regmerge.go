//go:build windows

package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/markov/corrivex/internal/choco"
	"github.com/markov/corrivex/internal/regscan"
	"github.com/markov/corrivex/internal/winget"
)

// fetchAgentConfig pulls the reg_scan_* settings from the server so the
// next regscan uses the admin-configured filters, not just defaults.
// Best-effort: on any failure we log and fall back to DefaultFilters.
func (r *Runtime) fetchAgentConfig() map[string]string {
	u := strings.TrimRight(r.Cfg.Server, "/") + "/api/?action=agent_config&hostname=" + mustHost()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil
	}
	if r.Cfg.APISecret != "" {
		req.Header.Set("X-API-Secret", r.Cfg.APISecret)
	}
	if r.Cfg.AgentToken != "" {
		req.Header.Set("X-Corrivex-Token", r.Cfg.AgentToken)
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

// mergeRegistry supplements the winget inventory with entries from the
// Windows uninstall registry trees. winget stays authoritative for apps
// it knows about; registry entries that fuzzy-match a winget row flip
// that row's Source column to "both" so the UI can show the agreement.
// Unmatched registry entries are appended with Source = "registry" and a
// `reg:` prefix on their ID (see regscan.SanitizeID).
//
// `logf` is the agent's WebSocket-backed log stream — used for one-line
// visibility into how many rows came from each source.
func (r *Runtime) mergeRegistry(winList []winget.Package, logf func(format string, a ...any)) []winget.Package {
	// Set the default source on every winget row so subsequent merges can
	// promote or extend the source tag cleanly.
	for i := range winList {
		if winList[i].Source == "" {
			winList[i].Source = "winget"
		}
	}

	// ---- Chocolatey merge ---------------------------------------------
	// Agents running Chocolatey get a full second inventory. Names that
	// collide with a winget row flip that row's source to "winget+choco";
	// unmatched choco rows join the list with a "choco:" prefixed id.
	winList = r.mergeChocolatey(winList, logf)

	// ---- Registry merge (as before) -----------------------------------
	var filters *regscan.Filters
	if cfg := r.fetchAgentConfig(); cfg != nil {
		f := regscan.FiltersFromSettings(cfg)
		filters = &f
		logf("regscan config: fetched %d server-side settings", len(cfg))
	} else {
		logf("regscan config: using defaults (server fetch failed)")
	}

	regList, err := regscan.ListInstalled(filters)
	if err != nil {
		logf("registry scan failed: %v", err)
		return winList
	}
	if len(regList) == 0 {
		return winList
	}

	// Index by normalised DisplayName for O(1) match.
	byName := make(map[string]int, len(winList))
	for i, p := range winList {
		byName[normalise(p.Name)] = i
	}

	added := 0
	promoted := 0
	for _, r := range regList {
		key := normalise(r.Name)
		if idx, ok := byName[key]; ok {
			if !strings.Contains(winList[idx].Source, "registry") {
				winList[idx].Source = mergeSourceTags(winList[idx].Source, "registry")
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
		logf("registry merge: +%d new, %d confirmed (registry)", added, promoted)
	}
	return winList
}

// mergeChocolatey appends Chocolatey-tracked packages into the merged
// list. Called once per full scan from mergeRegistry. Choco entries that
// match an existing winget row (by normalised name) flip the row's
// source tag from "winget" → "winget+choco"; unmatched entries arrive
// as new rows with source="chocolatey" and id="choco:<choco-id>" so the
// namespace never collides with winget ids.
func (r *Runtime) mergeChocolatey(winList []winget.Package, logf func(format string, a ...any)) []winget.Package {
	if !choco.IsInstalled() {
		// Respect the server-side toggle. Default is autoinstall=true so
		// every agent eventually picks up choco without admin action; set
		// the setting to "false" on air-gapped fleets where reaching
		// community.chocolatey.org/install.ps1 is impossible.
		if !r.chocoAutoinstallAllowed() {
			logf("choco: not installed, autoinstall disabled — skipping choco merge")
			return winList
		}
		logf("choco: not installed — running EnsureChoco bootstrap")
		if err := choco.EnsureChoco(logf); err != nil {
			logf("choco: bootstrap failed: %v — continuing without choco this scan", err)
			return winList
		}
		if !choco.IsInstalled() {
			// Script claimed success but Find() still comes up empty.
			logf("choco: bootstrap finished but choco.exe still not found on PATH — skipping")
			return winList
		}
	}

	// Fetch installed + outdated simultaneously so we know pending-upgrade
	// state for choco entries that end up in the list.
	installed, err := choco.ListInstalled()
	if err != nil {
		logf("choco list failed: %v", err)
		return winList
	}
	outdated, err := choco.ListUpgrades()
	if err != nil {
		// Non-fatal; still merge the installed inventory.
		logf("choco outdated failed: %v", err)
	}
	// Fast lookup: choco id → "available" version.
	available := make(map[string]string, len(outdated))
	for _, o := range outdated {
		available[strings.ToLower(o.ID)] = o.Available
	}

	byName := make(map[string]int, len(winList))
	for i, p := range winList {
		byName[normalise(p.Name)] = i
	}

	added := 0
	promoted := 0
	for _, c := range installed {
		key := normalise(c.Name)
		if idx, ok := byName[key]; ok {
			if !strings.Contains(winList[idx].Source, "choco") {
				winList[idx].Source = mergeSourceTags(winList[idx].Source, "choco")
				promoted++
			}
			continue
		}
		pkg := winget.Package{
			ID:      "choco:" + c.ID,
			Name:    c.Name,
			Version: c.Version,
			Source:  "chocolatey",
		}
		if v, ok := available[strings.ToLower(c.ID)]; ok {
			pkg.Available = v
		}
		winList = append(winList, pkg)
		added++
	}
	if added > 0 || promoted > 0 {
		logf("choco merge: +%d new, %d confirmed (winget+choco)", added, promoted)
	}
	return winList
}

// chocoAutoinstallAllowed is a cached wrapper around the
// choco_autoinstall server setting. Default true — matches the
// 1.7.0 changelog's promise that chocolatey bootstraps on every agent
// that doesn't already have it. Admins running air-gapped fleets can
// set the setting to "false" to keep the agent from reaching
// community.chocolatey.org.
func (r *Runtime) chocoAutoinstallAllowed() bool {
	cfg := r.fetchAgentConfig()
	if cfg == nil {
		return true
	}
	v, ok := cfg["choco_autoinstall"]
	if !ok {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// stripChocoPrefix returns the raw Chocolatey id without the `choco:`
// namespace prefix the merger adds. The agent stores ids as
// `choco:<id>` in the DB to avoid collisions with winget ids, but the
// choco CLI itself wants just `<id>`.
func stripChocoPrefix(id string) string {
	return strings.TrimPrefix(id, "choco:")
}

// mergeSourceTags joins two source tags deterministically. "winget" +
// "choco" → "winget+choco"; "winget" + "registry" → "winget+registry";
// already-joined tags are parsed and de-duplicated so repeated merges
// don't produce "winget+choco+choco".
func mergeSourceTags(a, b string) string {
	seen := map[string]bool{}
	order := []string{}
	for _, tag := range append(strings.Split(a, "+"), strings.Split(b, "+")...) {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		order = append(order, tag)
	}
	return strings.Join(order, "+")
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
