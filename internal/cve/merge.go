package cve

import (
	"strings"

	"github.com/markov/corrivex/internal/db"
)

func mergeCVEEntries(lists ...[]db.CVEEntry) []db.CVEEntry {
	byID := map[string]db.CVEEntry{}
	order := []string{}
	for _, list := range lists {
		for _, e := range list {
			if strings.TrimSpace(e.ID) == "" {
				continue
			}
			cur, ok := byID[e.ID]
			if !ok {
				byID[e.ID] = e
				order = append(order, e.ID)
				continue
			}
			cur.Source = mergeSource(cur.Source, e.Source)
			if cur.Severity == "" {
				cur.Severity = e.Severity
			}
			if cur.CVSS == 0 {
				cur.CVSS = e.CVSS
			}
			if cur.EPSS == 0 {
				cur.EPSS = e.EPSS
			}
			if cur.EPSSPercentile == 0 {
				cur.EPSSPercentile = e.EPSSPercentile
			}
			if cur.Summary == "" {
				cur.Summary = e.Summary
			}
			if cur.FixedVersion == "" {
				cur.FixedVersion = e.FixedVersion
			}
			if cur.Published == "" {
				cur.Published = e.Published
			}
			byID[e.ID] = cur
		}
	}
	out := make([]db.CVEEntry, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}

func mergeSource(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" || strings.Contains(","+a+",", ","+b+",") {
		return a
	}
	return a + "," + b
}
