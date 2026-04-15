package report

import "regexp"

var (
	reCVE  = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	reGHSA = regexp.MustCompile(`^GHSA-[a-z0-9-]+$`)
	reGO   = regexp.MustCompile(`^GO-\d+-\d+$`)
)
