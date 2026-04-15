package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/markov/corrivex/internal/version"
)

// PDFZipEntry is one (hostname, pdf bytes, row count) triple produced by the
// per-host batch. Exposed for the manifest.
type PDFZipEntry struct {
	Hostname string `json:"hostname"`
	Filename string `json:"filename"`
	Rows     int    `json:"rows"`
	Bytes    int    `json:"bytes"`
}

// PDFZip builds a zip containing one PDF per host for the given kind. The
// caller has already loaded the fleet-wide row slice and decides the hosts
// list (typically everything in `pcs`, so that hosts with zero rows still
// get a courtesy "no findings" PDF). When `hosts` is nil, the function
// derives the host set from the rows themselves.
//
// The zip also contains:
//   - README.txt   — one-line usage cover
//   - manifest.json — structured index ([]PDFZipEntry)
func PDFZip(kind string, rows any, hosts []string, scope, user string) (*Output, error) {
	buckets := PartitionByHost(kind, rows)

	// If hosts wasn't supplied, derive from buckets (sorted).
	if len(hosts) == 0 {
		for h := range buckets {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	manifest := make([]PDFZipEntry, 0, len(hosts))
	title, _ := titleFor(kind)

	for _, h := range hosts {
		hostRows := buckets[h]
		if hostRows == nil {
			hostRows = EmptyFor(kind)
		}
		pdfBytes, err := buildPDF(kind, hostRows, h, user)
		if err != nil {
			return nil, fmt.Errorf("pdf for %s: %w", h, err)
		}
		filename := reportFilename(kind, h, "pdf")
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     filename,
			Method:   zip.Deflate,
			Modified: time.Now(),
		})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(pdfBytes); err != nil {
			return nil, err
		}
		manifest = append(manifest, PDFZipEntry{
			Hostname: h,
			Filename: filename,
			Rows:     rowsCount(kind, hostRows),
			Bytes:    len(pdfBytes),
		})
	}

	// README.
	readme := fmt.Sprintf(`Corrivex · %s
generated %s
scope: %s
build:  v%s
hosts:  %d

This archive contains one PDF per host from the current Corrivex fleet.
Open each file in a PDF reader or print it directly. See manifest.json
for a structured index.
`, title, time.Now().UTC().Format("2006-01-02 15:04 UTC"), orDefault(scope, "fleet"),
		version.Version, len(manifest))
	if w, err := zw.Create("README.txt"); err == nil {
		_, _ = w.Write([]byte(readme))
	}

	// manifest.json.
	manBytes, _ := json.MarshalIndent(manifest, "", "  ")
	if w, err := zw.Create("manifest.json"); err == nil {
		_, _ = w.Write(manBytes)
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &Output{
		Body:        buf.Bytes(),
		ContentType: "application/zip",
		Filename:    reportFilename(kind, "per_host", "zip"),
	}, nil
}

func rowsCount(kind string, rows any) int {
	switch kind {
	case "installed_software":
		return len(asSoftware(rows))
	case "local_admins":
		return len(asAdmins(rows))
	case "cve_findings":
		return len(asCVEs(rows))
	}
	return 0
}

// versionForReadme avoids importing internal/version twice; the pdf.go file
// already does. This keeps the README tiny without an extra dep.
