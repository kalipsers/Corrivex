package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/markov/corrivex/internal/db"
)

const nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDClient queries NVD 2.0 CVE and CPE APIs. Free, no key needed, but
// without a key NVD rate limits aggressively, so the scanner serializes calls.
type NVDClient struct {
	HTTP        *http.Client
	APIKey      string
	Endpoint    string
	CPEEndpoint string
}

func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		APIKey:      apiKey,
		Endpoint:    nvdEndpoint,
		CPEEndpoint: "https://services.nvd.nist.gov/rest/json/cpes/2.0",
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
	CVSSData     nvdCVSSv2Data `json:"cvssData"`
	BaseSeverity string        `json:"baseSeverity"`
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
	Vulnerable       bool   `json:"vulnerable"`
	Criteria         string `json:"criteria"`
	VersionStartExcl string `json:"versionStartExcluding,omitempty"`
	VersionStartIncl string `json:"versionStartIncluding,omitempty"`
	VersionEndExcl   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncl   string `json:"versionEndIncluding,omitempty"`
}

func (c *NVDClient) Query(ctx context.Context, cpe CPE, version, confidence string) ([]db.CVEEntry, error) {
	if cpe.Vendor == "" || cpe.Product == "" {
		return nil, nil
	}
	match := fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", cpe.Vendor, cpe.Product)
	const pageSize = 200
	var entries []db.CVEEntry
	for start := 0; ; start += pageSize {
		q := url.Values{}
		q.Set("virtualMatchString", match)
		q.Set("resultsPerPage", fmt.Sprint(pageSize))
		if start > 0 {
			q.Set("startIndex", fmt.Sprint(start))
		}
		req, err := http.NewRequestWithContext(ctx, "GET", c.Endpoint+"?"+q.Encode(), nil)
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
		if resp.StatusCode == 404 {
			resp.Body.Close()
			return nil, nil
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("nvd HTTP %d", resp.StatusCode)
		}
		var out nvdResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()
		for _, w := range out.Vulnerabilities {
			if !cveAffectsVersion(w.CVE, cpe, version, confidence) {
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
		if out.TotalResults <= start+pageSize || len(out.Vulnerabilities) == 0 {
			break
		}
	}
	return entries, nil
}

type CPEMapping struct {
	PackageID  string
	CPE        CPE
	CPEName    string
	Title      string
	Confidence string
	Reason     string
	Source     string
}

type nvdCPEResponse struct {
	Products []nvdProduct `json:"products"`
}

type nvdProduct struct {
	CPE nvdCPE `json:"cpe"`
}

type nvdCPE struct {
	Deprecated bool           `json:"deprecated"`
	CPEName    string         `json:"cpeName"`
	Titles     []nvdCPEString `json:"titles"`
}

type nvdCPEString struct {
	Lang  string `json:"lang"`
	Title string `json:"title"`
}

func (c *NVDClient) DiscoverCPE(ctx context.Context, packageID, packageName string) (CPEMapping, error) {
	keywords := cpeKeywords(packageID, packageName)
	if len(keywords) == 0 {
		return CPEMapping{PackageID: packageID, Confidence: "none", Reason: "empty package identity", Source: "nvd_cpe"}, nil
	}
	var candidates []scoredCPE
	for _, keyword := range keywords {
		q := url.Values{}
		q.Set("keywordSearch", keyword)
		q.Set("resultsPerPage", "20")
		req, err := http.NewRequestWithContext(ctx, "GET", c.CPEEndpoint+"?"+q.Encode(), nil)
		if err != nil {
			return CPEMapping{}, err
		}
		req.Header.Set("User-Agent", "Corrivex-CVE-Scanner/1.0")
		if c.APIKey != "" {
			req.Header.Set("apiKey", c.APIKey)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return CPEMapping{}, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return CPEMapping{}, fmt.Errorf("nvd cpe HTTP %d", resp.StatusCode)
		}
		var out nvdCPEResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			resp.Body.Close()
			return CPEMapping{}, err
		}
		resp.Body.Close()
		for _, p := range out.Products {
			m := scoreCPECandidate(packageID, packageName, p.CPE)
			if m.score > 0 {
				candidates = append(candidates, m)
			}
		}
	}
	if len(candidates) == 0 {
		return CPEMapping{PackageID: packageID, Confidence: "none", Reason: "no CPE candidate", Source: "nvd_cpe"}, nil
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	return candidates[0].mapping, nil
}

type scoredCPE struct {
	score   int
	mapping CPEMapping
}

func scoreCPECandidate(packageID, packageName string, p nvdCPE) scoredCPE {
	part, cpe := parseCPEName(p.CPEName)
	if cpe.Vendor == "" || cpe.Product == "" || p.Deprecated {
		return scoredCPE{}
	}
	title := englishTitle(p.Titles)
	score := 0
	reasons := []string{}
	if part == "a" {
		score += 25
		reasons = append(reasons, "application CPE")
	}
	idVendor, idProduct := identityParts(packageID, packageName)
	if idVendor != "" && idVendor == normalizeToken(cpe.Vendor) {
		score += 20
		reasons = append(reasons, "vendor match")
	}
	if idProduct != "" && idProduct == normalizeToken(cpe.Product) {
		score += 30
		reasons = append(reasons, "product match")
	}
	if packageName != "" && strings.Contains(normalizeText(title), normalizeText(packageName)) {
		score += 30
		reasons = append(reasons, "title match")
	}
	if strings.Contains(normalizeText(title), idProduct) && idProduct != "" {
		score += 10
	}
	conf := "low"
	if score >= 70 {
		conf = "high"
	} else if score >= 45 {
		conf = "medium"
	}
	return scoredCPE{score: score, mapping: CPEMapping{
		PackageID:  packageID,
		CPE:        cpe,
		CPEName:    p.CPEName,
		Title:      title,
		Confidence: conf,
		Reason:     strings.Join(reasons, ", "),
		Source:     "nvd_cpe",
	}}
}

func parseCPEName(name string) (string, CPE) {
	parts := strings.Split(name, ":")
	if len(parts) < 5 {
		return "", CPE{}
	}
	return strings.ToLower(parts[2]), CPE{Vendor: strings.ToLower(parts[3]), Product: strings.ToLower(parts[4])}
}

func cpeKeyword(packageID, packageName string) string {
	if strings.TrimSpace(packageName) != "" {
		return strings.TrimSpace(packageName)
	}
	return strings.TrimSpace(strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(packageID))
}

func cpeKeywords(packageID, packageName string) []string {
	seen := map[string]bool{}
	add := func(out *[]string, v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[strings.ToLower(v)] {
			return
		}
		seen[strings.ToLower(v)] = true
		*out = append(*out, v)
	}
	var out []string
	add(&out, packageName)
	add(&out, strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(packageID))
	parts := strings.Split(packageID, ".")
	if len(parts) >= 2 {
		add(&out, parts[0]+" "+parts[1])
		add(&out, parts[1])
	}
	if len(out) == 0 {
		add(&out, cpeKeyword(packageID, packageName))
	}
	if len(out) > 4 {
		return out[:4]
	}
	return out
}

func englishTitle(titles []nvdCPEString) string {
	for _, t := range titles {
		if t.Lang == "en" && t.Title != "" {
			return t.Title
		}
	}
	if len(titles) > 0 {
		return titles[0].Title
	}
	return ""
}

func identityParts(packageID, packageName string) (string, string) {
	if packageID != "" {
		parts := strings.Split(packageID, ".")
		if len(parts) >= 2 {
			return normalizeToken(parts[0]), normalizeToken(parts[1])
		}
	}
	words := strings.Fields(strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(packageName))
	if len(words) == 0 {
		return "", ""
	}
	if len(words) == 1 {
		return normalizeToken(words[0]), normalizeToken(words[0])
	}
	return normalizeToken(words[0]), normalizeToken(words[len(words)-1])
}

func normalizeToken(s string) string {
	return strings.Trim(strings.ToLower(strings.NewReplacer("++", "pp", "+", "p", "-", "_", " ", "_", ".", "_").Replace(s)), "_")
}

func normalizeText(s string) string {
	return normalizeToken(s)
}

func cveAffectsVersion(cve nvdCVE, cpe CPE, version, confidence string) bool {
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
				tail := strings.TrimPrefix(crit, want)
				parts := strings.SplitN(tail, ":", 2)
				exactVer := parts[0]
				if m.VersionStartExcl != "" || m.VersionStartIncl != "" || m.VersionEndExcl != "" || m.VersionEndIncl != "" {
					if inRange(version, m.VersionStartExcl, m.VersionStartIncl, m.VersionEndExcl, m.VersionEndIncl) {
						return true
					}
					continue
				}
				if exactVer != "" && exactVer != "*" && exactVer != "-" && exactVer == lv {
					return true
				}
				if exactVer == "*" && confidence == "high" {
					return true
				}
			}
		}
	}
	return false
}

func inRange(v, startExcl, startIncl, endExcl, endIncl string) bool {
	if startExcl != "" && compareVer(v, startExcl) <= 0 {
		return false
	}
	if startIncl != "" && compareVer(v, startIncl) < 0 {
		return false
	}
	if endExcl != "" {
		return compareVer(v, endExcl) < 0
	}
	if endIncl != "" {
		return compareVer(v, endIncl) <= 0
	}
	return startExcl != "" || startIncl != ""
}

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
				if m.VersionEndIncl != "" {
					return m.VersionEndIncl
				}
			}
		}
	}
	return ""
}
