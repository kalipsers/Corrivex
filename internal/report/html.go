package report

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/version"
)

// HTMLData is the common payload every report template receives. Per-report
// fields are attached via the Rows interface (an any).
type htmlData struct {
	Title        string
	Subtitle     string
	Scope        string
	GeneratedAt  time.Time
	GeneratedBy  string
	AppVersion   string
	TotalRows    int
	Kind         string      // "installed_software" | "local_admins" | "cve_findings"
	Rows         any         // typed per Kind
	SummaryItems []summaryKV // small KV strip below the cover
}

type summaryKV struct {
	Label string
	Value string
}

// sevRank orders severities highest-first so templates can sort without
// custom pipelines.
func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// cveLinkForID mirrors the dashboard's cveAdvisoryURL so report hyperlinks
// land on the right advisory page.
func cveLinkForID(id string) string {
	if id == "" {
		return ""
	}
	// CVE-YYYY-NNNN (also embedded in ecosystem-prefixed IDs).
	if m := reCVE.FindString(id); m != "" {
		return "https://nvd.nist.gov/vuln/detail/" + m
	}
	if reGHSA.MatchString(id) {
		return "https://github.com/advisories/" + id
	}
	if reGO.MatchString(id) {
		return "https://pkg.go.dev/vuln/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}

var funcMap = template.FuncMap{
	"fmtTime":    func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"fmtDate":    func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"cveLink":    cveLinkForID,
	"sevRank":    sevRank,
	"lower":      func(s string) string { return lowercase(s) },
	"defaultStr": func(s, def string) string { if s == "" { return def }; return s },
	"add":        func(a, b int) int { return a + b },
}

// HTML renders the given dataset as a standalone HTML document. `rows` must
// match the `kind`:
//
//	installed_software → []db.InstalledSoftware
//	local_admins       → []db.LocalAdminEntry
//	cve_findings       → []db.CVEHostFinding
func HTML(kind string, rows any, scope, user string) (*Output, error) {
	t, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	data := htmlData{
		GeneratedAt: time.Now(),
		GeneratedBy: user,
		AppVersion:  version.Version,
		Scope:       scope,
		Kind:        kind,
		Rows:        rows,
	}
	switch kind {
	case "installed_software":
		sw, _ := rows.([]db.InstalledSoftware)
		data.Title = "Installed software inventory"
		data.Subtitle = "Snapshot of winget-tracked software per host"
		data.TotalRows = len(sw)
		data.SummaryItems = softwareSummary(sw)
	case "local_admins":
		ad, _ := rows.([]db.LocalAdminEntry)
		data.Title = "Local administrators"
		data.Subtitle = "Flattened list of (host, admin account) pairs"
		data.TotalRows = len(ad)
		data.SummaryItems = adminsSummary(ad)
	case "cve_findings":
		cv, _ := rows.([]db.CVEHostFinding)
		data.Title = "CVE findings"
		data.Subtitle = "Known vulnerabilities affecting installed software versions"
		data.TotalRows = len(cv)
		data.SummaryItems = cveSummary(cv)
	default:
		return nil, fmt.Errorf("unsupported html kind %q", kind)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, err
	}
	return &Output{
		Body:        buf.Bytes(),
		ContentType: "text/html; charset=utf-8",
		Filename:    reportFilename(kind, scope, "html"),
	}, nil
}

// -- per-report summary computations --------------------------------------

func softwareSummary(rows []db.InstalledSoftware) []summaryKV {
	hosts := map[string]bool{}
	pkgs := map[string]bool{}
	for _, r := range rows {
		hosts[r.Hostname] = true
		pkgs[r.PackageID] = true
	}
	return []summaryKV{
		{"Rows", itoa(len(rows))},
		{"Hosts represented", itoa(len(hosts))},
		{"Distinct packages", itoa(len(pkgs))},
	}
}

func adminsSummary(rows []db.LocalAdminEntry) []summaryKV {
	hosts := map[string]bool{}
	accts := map[string]bool{}
	for _, r := range rows {
		hosts[r.Hostname] = true
		accts[lowercase(r.AccountName)] = true
	}
	return []summaryKV{
		{"Rows", itoa(len(rows))},
		{"Hosts represented", itoa(len(hosts))},
		{"Distinct accounts", itoa(len(accts))},
	}
}

func cveSummary(rows []db.CVEHostFinding) []summaryKV {
	hosts := map[string]bool{}
	crit, high, kev := 0, 0, 0
	for _, r := range rows {
		hosts[r.Hostname] = true
		switch r.Severity {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		}
		if r.KEV {
			kev++
		}
	}
	return []summaryKV{
		{"Total findings", itoa(len(rows))},
		{"Affected hosts", itoa(len(hosts))},
		{"Critical", itoa(crit)},
		{"High", itoa(high)},
		{"KEV (actively exploited)", itoa(kev)},
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// lowercase is ASCII-only (enough for our hostnames/accounts), avoids pulling
// strings.ToLower into the template func map.
func lowercase(s string) string {
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		buf[i] = c
	}
	return string(buf)
}
