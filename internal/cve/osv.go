package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/markov/corrivex/internal/db"
)

const osvEndpoint = "https://api.osv.dev/v1/query"

// OSVClient queries osv.dev. Free, no key, no rate limit in practice.
type OSVClient struct {
	HTTP *http.Client
}

func NewOSVClient() *OSVClient {
	return &OSVClient{HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type osvRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string       `json:"id"`
	Summary   string       `json:"summary"`
	Details   string       `json:"details"`
	Aliases   []string     `json:"aliases"`
	Published string       `json:"published"`
	Severity  []osvSev     `json:"severity"`
	Affected  []osvAffect  `json:"affected"`
	DBSpec    osvSpecific  `json:"database_specific"`
}

type osvSev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffect struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type osvSpecific struct {
	Severity string `json:"severity"`
}

// Query asks OSV about a given package+version. The package name format
// depends on ecosystem; for Windows/winget apps we mostly strike out — OSV
// coverage there is thin — but for anything JS/Python/Go/Ruby/Rust/Java
// with a winget shim, OSV tends to have it. Best-effort: callers should
// fall back to NVD on empty result.
func (c *OSVClient) Query(ctx context.Context, pkgName, version, ecosystem string) ([]db.CVEEntry, error) {
	req := osvRequest{
		Package: osvPackage{Name: pkgName, Ecosystem: ecosystem},
		Version: version,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", osvEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("osv HTTP %d", resp.StatusCode)
	}
	var out osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// Pass 1: index canonical CVE-YYYY-NNNN entries so we don't emit a
	// distro-wrapped duplicate if the upstream record is present.
	seenCVE := map[string]bool{}
	for _, v := range out.Vulns {
		if strings.HasPrefix(v.ID, "CVE-") {
			seenCVE[v.ID] = true
		}
	}
	entries := make([]db.CVEEntry, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		// Drop Linux-distro tracker entries (UBUNTU-CVE-*, DEBIAN-CVE-*,
		// RHSA-*, ALAS-*, SUSE-SU-*). OSV surfaces them whenever a name
		// matches, but they track distro-packaged versions with
		// distro-specific versioning strings — useless when the host
		// actually installed the upstream winget build. The real
		// vulnerability, if it exists, is also published under a
		// canonical CVE-YYYY-NNNN entry; we rely on that or on NVD.
		if isDistroWrappedID(v.ID) {
			continue
		}
		if !osvVersionIsAffected(v.Affected, version) {
			continue
		}
		id := v.ID
		// Prefer canonical CVE ID if present in aliases.
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				id = a
				break
			}
		}
		_ = seenCVE // reserved for future dedup if needed
		entries = append(entries, db.CVEEntry{
			ID:           id,
			Severity:     strings.ToUpper(v.DBSpec.Severity),
			CVSS:         firstCVSS(v.Severity),
			Summary:      firstNonEmpty(v.Summary, v.Details),
			FixedVersion: firstFix(v.Affected),
			Published:    shortDate(v.Published),
			Source:       "osv",
		})
	}
	return entries, nil
}

// isDistroWrappedID returns true for OSV IDs that originate in a Linux
// distribution's CVE tracker. These entries describe distro-packaged
// versions and carry distro-specific version strings in their ranges,
// so matching them against a winget/Windows-native install is always
// wrong. The canonical CVE, when it exists, is separately indexed under
// its CVE-YYYY-NNNN ID.
func isDistroWrappedID(id string) bool {
	for _, p := range []string{
		"UBUNTU-CVE-", "DEBIAN-CVE-", "RHSA-", "ALAS-", "SUSE-SU-",
		"ALSA-", "ALEA-", "RLSA-", "USN-", "DSA-", "MGASA-",
	} {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// osvVersionIsAffected walks each affected/range/events list and decides
// whether `version` falls inside a vulnerable span. OSV events appear in
// ascending version order; the state machine toggles "introduced" on
// `introduced`/`last_affected` events and "not introduced" on `fixed`/`limit`.
//
// Returns true if any range reports the version as still in a vulnerable
// span. Ranges with no events at all leave the CVE in a conservative
// "include" state so we don't drop genuinely unbounded CVEs.
func osvVersionIsAffected(aff []osvAffect, version string) bool {
	if len(aff) == 0 {
		return true
	}
	saw := false
	for _, a := range aff {
		for _, r := range a.Ranges {
			if len(r.Events) == 0 {
				continue
			}
			saw = true
			if rangeAffectsVersion(r.Events, version) {
				return true
			}
		}
	}
	// If no ranges had any events at all, we have no way to filter — keep
	// the CVE. If at least one range had events but none matched, the CVE
	// is considered fixed/unaffected.
	return !saw
}

func rangeAffectsVersion(events []osvEvent, version string) bool {
	introduced := false
	for _, e := range events {
		switch {
		case e.Introduced == "0":
			introduced = true
		case e.Introduced != "":
			if compareVer(version, e.Introduced) >= 0 {
				introduced = true
			}
		case e.Fixed != "":
			if introduced && compareVer(version, e.Fixed) < 0 {
				return true
			}
			if compareVer(version, e.Fixed) >= 0 {
				introduced = false
			}
		case e.LastAffected != "":
			if introduced && compareVer(version, e.LastAffected) <= 0 {
				return true
			}
			if compareVer(version, e.LastAffected) > 0 {
				introduced = false
			}
		case e.Limit != "":
			// `limit` excludes versions ≥ limit from consideration (typically
			// the next major branch). Mirror the behaviour.
			if compareVer(version, e.Limit) >= 0 {
				introduced = false
			}
		}
	}
	// Reached the end while still flagged as introduced with no fix/limit —
	// version is inside an open-ended vulnerable range.
	return introduced
}

func firstCVSS(sev []osvSev) float64 {
	for _, s := range sev {
		if strings.HasPrefix(s.Type, "CVSS") {
			// Score is the full vector string; extract the base score if present.
			// Format: "CVSS:3.1/AV:N/AC:L/.../..." — base score isn't always here.
			// Return 0 when not parseable; caller sorts by severity string anyway.
			return 0
		}
	}
	return 0
}

func firstFix(aff []osvAffect) string {
	for _, a := range aff {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func shortDate(iso string) string {
	if len(iso) >= 10 {
		return iso[:10]
	}
	return iso
}
