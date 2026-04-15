// Package report encodes Corrivex's core data sets (installed software,
// local administrators, CVE findings) into downloadable formats. CSV + JSON
// are implemented in-process; PDF is planned for a later slice.
//
// Callers pass already-loaded data in from the db package — this package
// never talks to the database so it's trivially testable and easy to evolve
// without tripping the data layer.
package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/markov/corrivex/internal/db"
)

// Format is the wire format the caller requested.
type Format string

const (
	FormatCSV  Format = "csv"
	FormatJSON Format = "json"
	FormatHTML Format = "html"
)

// utf8BOM is prepended to CSV output so Excel opens it as UTF-8 instead of
// the local OEM code page. Without this, non-ASCII names (é, ü, č, 日本語)
// render as mojibake in Excel on Windows.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Output is the finished payload plus metadata the HTTP layer needs to set
// response headers.
type Output struct {
	Body        []byte
	ContentType string
	Filename    string // suggested filename for Content-Disposition
}

// -- Installed software -----------------------------------------------------

// InstalledSoftware encodes rows into the chosen format. `scope` is a human
// label ("fleet" or the hostname) used in the filename.
func InstalledSoftware(rows []db.InstalledSoftware, format Format, scope string) (*Output, error) {
	switch format {
	case FormatJSON:
		return jsonOutput(rows, reportFilename("installed_software", scope, "json"))
	case FormatCSV:
		var buf bytes.Buffer
		buf.Write(utf8BOM)
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"hostname", "package_id", "package_name", "version", "source", "first_seen", "last_seen"})
		for _, r := range rows {
			_ = w.Write([]string{
				r.Hostname, r.PackageID, r.PackageName, r.Version, r.Source,
				r.FirstSeen.UTC().Format(time.RFC3339),
				r.LastSeen.UTC().Format(time.RFC3339),
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return nil, err
		}
		return &Output{Body: buf.Bytes(), ContentType: "text/csv; charset=utf-8",
			Filename: reportFilename("installed_software", scope, "csv")}, nil
	}
	return nil, fmt.Errorf("unsupported format %q", format)
}

// -- Local administrators --------------------------------------------------

// LocalAdmins encodes admin entries into CSV or JSON.
func LocalAdmins(rows []db.LocalAdminEntry, format Format, scope string) (*Output, error) {
	switch format {
	case FormatJSON:
		return jsonOutput(rows, reportFilename("local_admins", scope, "json"))
	case FormatCSV:
		var buf bytes.Buffer
		buf.Write(utf8BOM)
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"hostname", "domain", "account", "type", "enabled"})
		for _, r := range rows {
			_ = w.Write([]string{
				r.Hostname, r.Domain, r.AccountName, r.AccountType,
				strconv.FormatBool(r.Enabled),
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return nil, err
		}
		return &Output{Body: buf.Bytes(), ContentType: "text/csv; charset=utf-8",
			Filename: reportFilename("local_admins", scope, "csv")}, nil
	}
	return nil, fmt.Errorf("unsupported format %q", format)
}

// -- CVE findings -----------------------------------------------------------

// CVEFindings encodes per-host CVE findings. One row per (host, package, CVE)
// so spreadsheets can pivot on any dimension.
func CVEFindings(rows []db.CVEHostFinding, format Format, scope string) (*Output, error) {
	switch format {
	case FormatJSON:
		return jsonOutput(rows, reportFilename("cve_findings", scope, "json"))
	case FormatCSV:
		var buf bytes.Buffer
		buf.Write(utf8BOM)
		w := csv.NewWriter(&buf)
		_ = w.Write([]string{"hostname", "package_id", "package_name", "version",
			"cve_id", "severity", "cvss", "kev", "fixed_version", "published",
			"source", "summary"})
		for _, r := range rows {
			cvss := ""
			if r.CVSS > 0 {
				cvss = strconv.FormatFloat(r.CVSS, 'f', 1, 64)
			}
			_ = w.Write([]string{
				r.Hostname, r.PackageID, r.PackageName, r.Version,
				r.CVEID, r.Severity, cvss, strconv.FormatBool(r.KEV),
				r.FixedIn, r.Published, r.Source, r.Summary,
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return nil, err
		}
		return &Output{Body: buf.Bytes(), ContentType: "text/csv; charset=utf-8",
			Filename: reportFilename("cve_findings", scope, "csv")}, nil
	}
	return nil, fmt.Errorf("unsupported format %q", format)
}

// -- shared helpers ---------------------------------------------------------

func jsonOutput(v any, filename string) (*Output, error) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &Output{
		Body:        body,
		ContentType: "application/json; charset=utf-8",
		Filename:    filename,
	}, nil
}

// reportFilename builds a stable, filesystem-friendly filename for the
// Content-Disposition header: `corrivex_<type>_<scope>_<yyyymmdd>.<ext>`.
func reportFilename(reportType, scope, ext string) string {
	if scope == "" {
		scope = "fleet"
	}
	stamp := time.Now().UTC().Format("20060102")
	return fmt.Sprintf("corrivex_%s_%s_%s.%s", reportType, safeScope(scope), stamp, ext)
}

// safeScope sanitises a hostname or label so it fits in a filename without
// quoting drama. Lowercases and replaces any non-[a-z0-9_-] with '-'.
func safeScope(s string) string {
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			buf = append(buf, c+32)
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-':
			buf = append(buf, c)
		default:
			buf = append(buf, '-')
		}
	}
	if len(buf) == 0 {
		return "fleet"
	}
	return string(buf)
}
