package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/markov/corrivex/internal/db"
)

const nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDClient queries NVD 2.0 by CPE match string. Free, no key needed, but
// without a key you get 5 req / 30s — so the scanner serialises per-host
// work to stay under it.
type NVDClient struct {
	HTTP   *http.Client
	APIKey string // optional — from NVD_API_KEY env var, lifts rate limit to 50/30s
}

func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{
		HTTP:   &http.Client{Timeout: 30 * time.Second},
		APIKey: apiKey,
	}
}

type nvdResponse struct {
	TotalResults    int              `json:"totalResults"`
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string         `json:"id"`
	Published    string         `json:"published"`
	Descriptions []nvdLangValue `json:"descriptions"`
	Metrics      nvdMetrics     `json:"metrics"`
	Configs      []nvdConfig    `json:"configurations"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdCVSSv3 `json:"cvssMetricV31"`
	V30 []nvdCVSSv3 `json:"cvssMetricV30"`
	V2  []nvdCVSSv2 `json:"cvssMetricV2"`
}

type nvdCVSSv3 struct {
	CVSSData nvdCVSSv3Data `json:"cvssData"`
}

type nvdCVSSv3Data struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdCVSSv2 struct {
	CVSSData    nvdCVSSv2Data `json:"cvssData"`
	BaseSeverity string       `json:"baseSeverity"`
}

type nvdCVSSv2Data struct {
	BaseScore float64 `json:"baseScore"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable      bool   `json:"vulnerable"`
	Criteria        string `json:"criteria"`
	VersionEndExcl  string `json:"versionEndExcluding,omitempty"`
	VersionEndIncl  string `json:"versionEndIncluding,omitempty"`
}

// Query asks NVD for all CVEs matching a vendor:product:version CPE. Returns
// the subset whose version range includes `version` on at least one affected
// configuration.
//
// Construction: we pass `cpeName=cpe:2.3:a:<vendor>:<product>:<version>:*`
// as `virtualMatchString` which uses NVD's CPE-aware matching. Then locally
// filter out rows where the version doesn't fall in the affected range.
func (c *NVDClient) Query(ctx context.Context, cpe CPE, version string) ([]db.CVEEntry, error) {
	if cpe.Vendor == "" || cpe.Product == "" {
		return nil, nil
	}
	// Build a virtualMatchString. Leaving version as `*` gets all CVEs for
	// the product; we'll filter by range locally (NVD's server-side version
	// filtering on virtualMatchString is flaky).
	match := fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", cpe.Vendor, cpe.Product)
	q := url.Values{}
	q.Set("virtualMatchString", match)
	q.Set("resultsPerPage", "200")
	req, err := http.NewRequestWithContext(ctx, "GET", nvdEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Corrivex-CVE-Scanner/1.0")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nvd HTTP %d", resp.StatusCode)
	}
	var out nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	entries := make([]db.CVEEntry, 0, len(out.Vulnerabilities))
	for _, w := range out.Vulnerabilities {
		if !cveAffectsVersion(w.CVE, cpe, version) {
			continue
		}
		entries = append(entries, db.CVEEntry{
			ID:           w.CVE.ID,
			Severity:     strings.ToUpper(bestSeverity(w.CVE.Metrics)),
			CVSS:         bestCVSS(w.CVE.Metrics),
			Summary:      englishDesc(w.CVE.Descriptions),
			FixedVersion: fixedVersion(w.CVE, cpe),
			Published:    shortDate(w.CVE.Published),
			Source:       "nvd",
		})
	}
	return entries, nil
}

func cveAffectsVersion(cve nvdCVE, cpe CPE, version string) bool {
	want := strings.ToLower(fmt.Sprintf("cpe:2.3:a:%s:%s:", cpe.Vendor, cpe.Product))
	lv := strings.ToLower(version)
	for _, cfg := range cve.Configs {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				crit := strings.ToLower(m.Criteria)
				if !strings.HasPrefix(crit, want) {
					continue
				}
				// Tail: "<version>:<update>:..." after the prefix.
				tail := strings.TrimPrefix(crit, want)
				parts := strings.SplitN(tail, ":", 2)
				exactVer := parts[0]
				// Range match — the authoritative case. Most modern NVD
				// entries express vulnerability as "product:* … endExcluding=X".
				if m.VersionEndExcl != "" || m.VersionEndIncl != "" {
					if inRange(version, "", m.VersionEndExcl, m.VersionEndIncl) {
						return true
					}
					continue
				}
				// Exact-version match — covers entries that pin a single
				// vulnerable build.
				if exactVer != "" && exactVer != "*" && exactVer != "-" && exactVer == lv {
					return true
				}
				// Wildcard with no range bounds intentionally ignored: NVD
				// historical data contains many rows like `edge:*` with no
				// bounds, covering CVEs for the Internet-Explorer-era
				// pre-Chromium Edge (2015-2018) or Flash plugins. Matching
				// them against modern Edge 147 produces hundreds of false
				// positives. Callers trade the occasional missed "affects
				// all versions" CVE for a vastly cleaner signal.
			}
		}
	}
	return false
}

// inRange returns true if `v` is strictly less than endExcl (if set) or
// less-equal to endIncl (if set). Uses Go's simple string compare, which
// is good enough for dotted-numeric versions in the common case. For edge
// cases (pre-releases, non-numeric suffixes) it can produce false positives
// — we accept that over missing a real vuln.
func inRange(v, _, endExcl, endIncl string) bool {
	if endExcl != "" && compareVer(v, endExcl) < 0 {
		return true
	}
	if endIncl != "" && compareVer(v, endIncl) <= 0 {
		return true
	}
	return false
}

// compareVer does a numeric-aware compare of dotted versions. Returns
// negative if a<b, 0 if equal, positive if a>b. Non-numeric segments fall
// back to string compare.
func compareVer(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var ap, bp string
		if i < len(as) {
			ap = as[i]
		}
		if i < len(bs) {
			bp = bs[i]
		}
		ai, aok := parseInt(ap)
		bi, bok := parseInt(bp)
		if aok && bok {
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
			continue
		}
		if ap != bp {
			if ap < bp {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseInt(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func bestSeverity(m nvdMetrics) string {
	if len(m.V31) > 0 {
		return m.V31[0].CVSSData.BaseSeverity
	}
	if len(m.V30) > 0 {
		return m.V30[0].CVSSData.BaseSeverity
	}
	if len(m.V2) > 0 {
		return m.V2[0].BaseSeverity
	}
	return ""
}

func bestCVSS(m nvdMetrics) float64 {
	if len(m.V31) > 0 {
		return m.V31[0].CVSSData.BaseScore
	}
	if len(m.V30) > 0 {
		return m.V30[0].CVSSData.BaseScore
	}
	if len(m.V2) > 0 {
		return m.V2[0].CVSSData.BaseScore
	}
	return 0
}

func englishDesc(ds []nvdLangValue) string {
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

func fixedVersion(cve nvdCVE, cpe CPE) string {
	want := strings.ToLower(fmt.Sprintf("cpe:2.3:a:%s:%s:", cpe.Vendor, cpe.Product))
	for _, cfg := range cve.Configs {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				if !strings.HasPrefix(strings.ToLower(m.Criteria), want) {
					continue
				}
				if m.VersionEndExcl != "" {
					return m.VersionEndExcl
				}
			}
		}
	}
	return ""
}
