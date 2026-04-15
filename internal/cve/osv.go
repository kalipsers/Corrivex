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
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
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
	entries := make([]db.CVEEntry, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		id := v.ID
		// Prefer canonical CVE ID if present in aliases.
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				id = a
				break
			}
		}
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
