package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/markov/corrivex/internal/db"
)

type GitHubAdvisoryClient struct {
	HTTP     *http.Client
	Token    string
	Endpoint string
}

type GitHubPackage struct {
	Ecosystem string
	Name      string
}

func NewGitHubAdvisoryClient(token string) *GitHubAdvisoryClient {
	return &GitHubAdvisoryClient{
		HTTP:     &http.Client{Timeout: 20 * time.Second},
		Token:    token,
		Endpoint: "https://api.github.com/advisories",
	}
}

type ghAdvisory struct {
	GHSAID          string            `json:"ghsa_id"`
	CVEID           string            `json:"cve_id"`
	Summary         string            `json:"summary"`
	Severity        string            `json:"severity"`
	PublishedAt     string            `json:"published_at"`
	Vulnerabilities []ghVulnerability `json:"vulnerabilities"`
	CVSS            struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
}

type ghVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	FirstPatchedVersion    any    `json:"first_patched_version"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
}

func (c *GitHubAdvisoryClient) Query(ctx context.Context, pkg GitHubPackage, version string) ([]db.CVEEntry, error) {
	if pkg.Ecosystem == "" || pkg.Name == "" {
		return nil, nil
	}
	q := url.Values{}
	q.Set("ecosystem", pkg.Ecosystem)
	q.Set("affects", pkg.Name)
	req, err := http.NewRequestWithContext(ctx, "GET", c.Endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Corrivex-CVE-Scanner/1.0")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
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
		return nil, fmt.Errorf("github advisory HTTP %d", resp.StatusCode)
	}
	var advisories []ghAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, err
	}
	var out []db.CVEEntry
	for _, adv := range advisories {
		for _, v := range adv.Vulnerabilities {
			if !strings.EqualFold(v.Package.Ecosystem, pkg.Ecosystem) || !strings.EqualFold(v.Package.Name, pkg.Name) {
				continue
			}
			if !versionSatisfiesRange(version, v.VulnerableVersionRange) {
				continue
			}
			out = append(out, db.CVEEntry{
				ID:           firstNonEmpty(adv.CVEID, adv.GHSAID),
				Severity:     strings.ToUpper(adv.Severity),
				CVSS:         adv.CVSS.Score,
				Summary:      adv.Summary,
				FixedVersion: patchedVersion(v.FirstPatchedVersion),
				Published:    shortDate(adv.PublishedAt),
				Source:       "github",
			})
		}
	}
	return out, nil
}

func patchedVersion(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		if s, ok := x["identifier"].(string); ok {
			return s
		}
	}
	return ""
}

func versionSatisfiesRange(version, expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	for _, group := range strings.Split(expr, "||") {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		ok := true
		for _, term := range versionTerms(group) {
			if !versionSatisfiesTerm(version, term) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func versionTerms(group string) []string {
	group = strings.ReplaceAll(group, ",", " ")
	fields := strings.Fields(group)
	var out []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if isVersionOperator(f) && i+1 < len(fields) {
			out = append(out, f+fields[i+1])
			i++
			continue
		}
		out = append(out, f)
	}
	return out
}

func isVersionOperator(s string) bool {
	switch s {
	case "<", "<=", ">", ">=", "=":
		return true
	default:
		return false
	}
}

func versionSatisfiesTerm(version, term string) bool {
	term = strings.TrimSpace(term)
	if term == "" || term == "*" {
		return true
	}
	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(term, op) {
			target := strings.TrimSpace(strings.TrimPrefix(term, op))
			cmp := compareVer(version, target)
			switch op {
			case ">=":
				return cmp >= 0
			case "<=":
				return cmp <= 0
			case ">":
				return cmp > 0
			case "<":
				return cmp < 0
			case "=":
				return cmp == 0
			}
		}
	}
	if strings.HasPrefix(term, "~>") || strings.HasPrefix(term, "^") {
		return false
	}
	return compareVer(version, term) == 0
}

func parseFloatString(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}
