package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/consts/orientation"
	"github.com/johnfercher/maroto/v2/pkg/consts/pagesize"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/version"
)

// Brand palette — reuses the Trust & Authority values from the HTML
// template so screen and paper share a visual language.
var (
	inkColor    = props.Color{Red: 15, Green: 23, Blue: 42}
	inkColor2   = props.Color{Red: 51, Green: 65, Blue: 85}
	mutedColor  = props.Color{Red: 100, Green: 116, Blue: 139}
	ruleColor   = props.Color{Red: 203, Green: 213, Blue: 225}
	rule2Color  = props.Color{Red: 226, Green: 232, Blue: 240}
	panelColor  = props.Color{Red: 248, Green: 250, Blue: 252}
	zebraColor  = props.Color{Red: 252, Green: 252, Blue: 253}
	dangerColor = props.Color{Red: 153, Green: 27, Blue: 27}
	warnColor   = props.Color{Red: 146, Green: 64, Blue: 14}
	okColor     = props.Color{Red: 22, Green: 101, Blue: 52}
)

// PDF renders a report as a PDF for the given kind + row set. Callers pass
// already-loaded data (no DB access here).
func PDF(kind string, rows any, scope, user string) (*Output, error) {
	b, err := buildPDF(kind, rows, scope, user)
	if err != nil {
		return nil, err
	}
	return &Output{
		Body:        b,
		ContentType: "application/pdf",
		Filename:    reportFilename(kind, scope, "pdf"),
	}, nil
}

func buildPDF(kind string, rows any, scope, user string) ([]byte, error) {
	title, subtitle := titleFor(kind)
	totalRows, summary := summaryFor(kind, rows)

	cfg := config.NewBuilder().
		WithPageSize(pagesize.A4).
		WithOrientation(orientation.Vertical).
		WithTopMargin(18).
		WithBottomMargin(20).
		WithLeftMargin(14).
		WithRightMargin(14).
		WithDefaultFont(&props.Font{Family: "Helvetica", Size: 9, Color: &inkColor}).
		WithAuthor("Corrivex", false).
		WithCreator("Corrivex v"+version.Version, false).
		WithTitle(title, false).
		WithPageNumber(props.PageNumber{
			Pattern: "Corrivex · page {current} / {total}",
			Place:   props.Bottom,
			Size:    8,
			Color:   &mutedColor,
		}).
		Build()

	m := maroto.New(cfg)

	// Footer: report title on the left of each page.
	_ = m.RegisterFooter(
		row.New(4).Add(
			text.NewCol(12, fmt.Sprintf("%s · scope: %s", title, orDefault(scope, "fleet")),
				props.Text{Size: 7, Color: &mutedColor, Align: align.Left}),
		),
	)

	// Cover block.
	m.AddRow(5, text.NewCol(12, "CORRIVEX · ENDPOINT PATCH MANAGEMENT",
		props.Text{Size: 7, Style: fontstyle.Bold, Color: &mutedColor, Align: align.Left}))

	m.AddRow(12,
		text.NewCol(8, title,
			props.Text{Size: 20, Style: fontstyle.Bold, Color: &inkColor, Align: align.Left}),
		text.NewCol(4, "SCOPE "+strings.ToUpper(orDefault(scope, "fleet")),
			props.Text{Size: 8, Style: fontstyle.Bold, Color: &mutedColor, Align: align.Right, Top: 3}),
	)
	m.AddRow(6,
		text.NewCol(8, subtitle,
			props.Text{Size: 10, Color: &inkColor2, Align: align.Left}),
		text.NewCol(4, "GENERATED "+time.Now().UTC().Format("2006-01-02 15:04 UTC"),
			props.Text{Size: 8, Color: &mutedColor, Align: align.Right}),
	)
	m.AddRow(4,
		col.New(8),
		text.NewCol(4, fmt.Sprintf("BUILD v%s%s", version.Version, byUser(user)),
			props.Text{Size: 8, Color: &mutedColor, Align: align.Right}),
	)

	// Rule under the cover.
	m.AddRow(0.4).WithStyle(&props.Cell{BackgroundColor: &ruleColor})
	m.AddRow(3, col.New(12))

	// Summary band.
	if len(summary) > 0 {
		gridPer := 12 / len(summary)
		if gridPer < 2 {
			gridPer = 2
		}
		labelCols := make([]core.Col, 0, len(summary))
		valueCols := make([]core.Col, 0, len(summary))
		used := 0
		for i, it := range summary {
			size := gridPer
			if i == len(summary)-1 {
				size = 12 - used
				if size < 2 {
					size = 2
				}
			}
			used += size
			labelCols = append(labelCols, text.NewCol(size, strings.ToUpper(it.Label),
				props.Text{Size: 7, Style: fontstyle.Bold, Color: &mutedColor, Align: align.Left, Left: 2, Top: 1.5}))
			valueCols = append(valueCols, text.NewCol(size, it.Value,
				props.Text{Size: 14, Style: fontstyle.Bold, Color: &inkColor, Align: align.Left, Left: 2, Top: 1}))
		}
		m.AddRow(5, labelCols...).WithStyle(&props.Cell{BackgroundColor: &panelColor})
		m.AddRow(7, valueCols...).WithStyle(&props.Cell{BackgroundColor: &panelColor})
		m.AddRow(4, col.New(12))
	}

	// Data table.
	switch kind {
	case "installed_software":
		renderSoftwareTable(m, asSoftware(rows))
	case "local_admins":
		renderAdminsTable(m, asAdmins(rows))
	case "cve_findings":
		renderCVETable(m, asCVEs(rows))
	default:
		return nil, fmt.Errorf("unsupported pdf kind %q", kind)
	}

	if totalRows == 0 {
		m.AddRow(15, text.NewCol(12, "No rows to report for this scope.",
			props.Text{Size: 10, Color: &mutedColor, Align: align.Center, Top: 5}))
	}

	doc, err := m.Generate()
	if err != nil {
		return nil, err
	}
	return doc.GetBytes(), nil
}

// Table head — emits a single header row with the given labels.
func addTableHead(m core.Maroto, cols []tableCol) {
	rowCols := make([]core.Col, 0, len(cols))
	for _, c := range cols {
		rowCols = append(rowCols, text.NewCol(c.Size, c.Label,
			props.Text{Size: 7, Style: fontstyle.Bold, Color: &mutedColor, Align: align.Left, Left: 2, Top: 1.5}))
	}
	m.AddRow(5, rowCols...).WithStyle(&props.Cell{BackgroundColor: &panelColor})
}

type tableCol struct {
	Label string
	Size  int
}

func renderSoftwareTable(m core.Maroto, rows []db.InstalledSoftware) {
	addTableHead(m, []tableCol{
		{"HOST", 2}, {"PACKAGE ID", 3}, {"NAME", 3}, {"VERSION", 2}, {"LAST SEEN", 2},
	})
	for i, r := range rows {
		bg := (*props.Color)(nil)
		if i%2 == 1 {
			bg = &zebraColor
		}
		m.AddRow(4,
			text.NewCol(2, r.Hostname, props.Text{Size: 8, Style: fontstyle.Bold, Left: 2, Top: 1}),
			text.NewCol(3, r.PackageID, props.Text{Size: 7, Family: "Courier", Color: &inkColor2, Left: 2, Top: 1}),
			text.NewCol(3, orDefault(r.PackageName, "—"), props.Text{Size: 8, Left: 2, Top: 1}),
			text.NewCol(2, orDefault(r.Version, "—"), props.Text{Size: 7, Family: "Courier", Left: 2, Top: 1}),
			text.NewCol(2, r.LastSeen.UTC().Format("2006-01-02"), props.Text{Size: 7, Family: "Courier", Color: &mutedColor, Left: 2, Top: 1}),
		).WithStyle(&props.Cell{BackgroundColor: bg})
	}
}

func renderAdminsTable(m core.Maroto, rows []db.LocalAdminEntry) {
	addTableHead(m, []tableCol{
		{"HOST", 3}, {"DOMAIN", 2}, {"ACCOUNT", 4}, {"TYPE", 2}, {"ENABLED", 1},
	})
	for i, r := range rows {
		bg := (*props.Color)(nil)
		if i%2 == 1 {
			bg = &zebraColor
		}
		enabled := "—"
		enabledColor := &mutedColor
		if r.Enabled {
			enabled = "yes"
			enabledColor = &okColor
		}
		m.AddRow(4,
			text.NewCol(3, r.Hostname, props.Text{Size: 8, Style: fontstyle.Bold, Left: 2, Top: 1}),
			text.NewCol(2, orDefault(r.Domain, "—"), props.Text{Size: 7, Color: &mutedColor, Left: 2, Top: 1}),
			text.NewCol(4, r.AccountName, props.Text{Size: 7, Family: "Courier", Left: 2, Top: 1}),
			text.NewCol(2, orDefault(r.AccountType, "—"), props.Text{Size: 7, Color: &mutedColor, Left: 2, Top: 1}),
			text.NewCol(1, enabled, props.Text{Size: 7, Color: enabledColor, Left: 2, Top: 1}),
		).WithStyle(&props.Cell{BackgroundColor: bg})
	}
}

func renderCVETable(m core.Maroto, rows []db.CVEHostFinding) {
	addTableHead(m, []tableCol{
		{"HOST", 2}, {"CVE", 2}, {"SEV", 1}, {"PACKAGE", 3}, {"VER", 1}, {"FIXED", 1}, {"SUMMARY", 2},
	})
	for i, r := range rows {
		bg := (*props.Color)(nil)
		if i%2 == 1 {
			bg = &zebraColor
		}
		sevLabel, sevColor := sevDisplay(r.Severity)
		if r.KEV {
			sevLabel += "·KEV"
			sevColor = &dangerColor
		}
		m.AddRow(5,
			text.NewCol(2, r.Hostname, props.Text{Size: 7, Style: fontstyle.Bold, Left: 2, Top: 1}),
			text.NewCol(2, r.CVEID, props.Text{Size: 6, Family: "Courier", Color: &inkColor2, Left: 2, Top: 1}),
			text.NewCol(1, sevLabel, props.Text{Size: 6, Style: fontstyle.Bold, Color: sevColor, Left: 2, Top: 1}),
			text.NewCol(3, orDefault(r.PackageName, r.PackageID), props.Text{Size: 7, Left: 2, Top: 1}),
			text.NewCol(1, orDefault(r.Version, "—"), props.Text{Size: 6, Family: "Courier", Left: 2, Top: 1}),
			text.NewCol(1, orDefault(r.FixedIn, "—"), props.Text{Size: 6, Family: "Courier", Color: &mutedColor, Left: 2, Top: 1}),
			text.NewCol(2, truncate(r.Summary, 120), props.Text{Size: 6, Color: &inkColor2, Left: 2, Top: 1}),
		).WithStyle(&props.Cell{BackgroundColor: bg})
	}
}

// ---- helpers ------------------------------------------------------------

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func byUser(u string) string {
	if u == "" {
		return ""
	}
	return " · by " + u
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func sevDisplay(s string) (string, *props.Color) {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "CRIT", &dangerColor
	case "HIGH":
		return "HIGH", &dangerColor
	case "MEDIUM":
		return "MED", &warnColor
	case "LOW":
		return "LOW", &inkColor2
	}
	return "—", &mutedColor
}

// Row partitioning helpers used by the ZIP batch.

func asSoftware(r any) []db.InstalledSoftware { v, _ := r.([]db.InstalledSoftware); return v }
func asAdmins(r any) []db.LocalAdminEntry     { v, _ := r.([]db.LocalAdminEntry); return v }
func asCVEs(r any) []db.CVEHostFinding        { v, _ := r.([]db.CVEHostFinding); return v }

// titleFor returns the same (title, subtitle) pair html.go uses so the two
// output formats stay in lockstep.
func titleFor(kind string) (string, string) {
	switch kind {
	case "installed_software":
		return "Installed software inventory", "Snapshot of winget-tracked software per host"
	case "local_admins":
		return "Local administrators", "Flattened list of (host, admin account) pairs"
	case "cve_findings":
		return "CVE findings", "Known vulnerabilities affecting installed software versions"
	}
	return "Report", ""
}

// summaryFor returns (total, KV pairs) using html.go's helpers.
func summaryFor(kind string, rows any) (int, []summaryKV) {
	switch kind {
	case "installed_software":
		sw := asSoftware(rows)
		return len(sw), softwareSummary(sw)
	case "local_admins":
		ad := asAdmins(rows)
		return len(ad), adminsSummary(ad)
	case "cve_findings":
		cv := asCVEs(rows)
		return len(cv), cveSummary(cv)
	}
	return 0, nil
}

// PartitionByHost groups a homogenous row slice by hostname. Used by the
// per-host ZIP batch to produce one PDF per host.
func PartitionByHost(kind string, rows any) map[string]any {
	out := map[string]any{}
	switch kind {
	case "installed_software":
		bucket := map[string][]db.InstalledSoftware{}
		for _, r := range asSoftware(rows) {
			bucket[r.Hostname] = append(bucket[r.Hostname], r)
		}
		for h, v := range bucket {
			out[h] = v
		}
	case "local_admins":
		bucket := map[string][]db.LocalAdminEntry{}
		for _, r := range asAdmins(rows) {
			bucket[r.Hostname] = append(bucket[r.Hostname], r)
		}
		for h, v := range bucket {
			out[h] = v
		}
	case "cve_findings":
		bucket := map[string][]db.CVEHostFinding{}
		for _, r := range asCVEs(rows) {
			bucket[r.Hostname] = append(bucket[r.Hostname], r)
		}
		for h, v := range bucket {
			out[h] = v
		}
	}
	return out
}

// EmptyFor returns a zero-length slice of the right concrete type for the
// kind. Used when a host is in the inventory but has no matching rows.
func EmptyFor(kind string) any {
	switch kind {
	case "installed_software":
		return []db.InstalledSoftware{}
	case "local_admins":
		return []db.LocalAdminEntry{}
	case "cve_findings":
		return []db.CVEHostFinding{}
	}
	return nil
}
