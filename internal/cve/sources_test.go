package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/markov/corrivex/internal/db"
)

func TestNVDQueryPaginatesAndHonorsStartEndRanges(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("startIndex") == "200" {
			w.Write([]byte(`{
				"totalResults": 201,
				"vulnerabilities": [{
					"cve": {
						"id": "CVE-2099-0002",
						"published": "2099-01-02T00:00:00.000",
						"descriptions": [{"lang":"en","value":"affected"}],
						"metrics": {"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH","baseScore":8.1}}]},
						"configurations": [{"nodes":[{"cpeMatch":[{
							"vulnerable": true,
							"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
							"versionStartIncluding": "1.0.0",
							"versionEndExcluding": "2.0.0"
						}]}]}]
					}
				}]
			}`))
			return
		}
		w.Write([]byte(`{
			"totalResults": 201,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2099-0001",
					"descriptions": [{"lang":"en","value":"not affected"}],
					"configurations": [{"nodes":[{"cpeMatch":[{
						"vulnerable": true,
						"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						"versionStartIncluding": "3.0.0"
					}]}]}]
				}
			}]
		}`))
	}))
	defer srv.Close()

	c := NewNVDClient("")
	c.Endpoint = srv.URL
	got, err := c.Query(context.Background(), CPE{Vendor: "vendor", Product: "product"}, "1.5.0", "high")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d want pagination across two pages", calls)
	}
	if len(got) != 1 || got[0].ID != "CVE-2099-0002" {
		t.Fatalf("got=%v", got)
	}
}

func TestNVDDiscoverCPESelectsHighConfidenceApplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"products": [
				{"cpe": {"deprecated": false, "cpeName": "cpe:2.3:o:google:chrome_os:*:*:*:*:*:*:*:*", "titles": [{"lang":"en","title":"Google Chrome OS"}]}},
				{"cpe": {"deprecated": false, "cpeName": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "titles": [{"lang":"en","title":"Google Chrome"}]}},
				{"cpe": {"deprecated": true, "cpeName": "cpe:2.3:a:google:old_chrome:*:*:*:*:*:*:*:*", "titles": [{"lang":"en","title":"Google Chrome old"}]}}
			]
		}`))
	}))
	defer srv.Close()

	c := NewNVDClient("")
	c.CPEEndpoint = srv.URL
	m, err := c.DiscoverCPE(context.Background(), "Google.Chrome", "Google Chrome")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if m.CPE.Vendor != "google" || m.CPE.Product != "chrome" || m.Confidence != "high" {
		t.Fatalf("mapping=%+v", m)
	}
	if !strings.Contains(m.Reason, "title") {
		t.Fatalf("reason=%q", m.Reason)
	}
}

func TestOSVQueryFixedVersionExcluded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"vulns":[{"id":"CVE-2099-0003","summary":"fixed","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}]}`))
	}))
	defer srv.Close()

	c := NewOSVClient()
	c.Endpoint = srv.URL
	got, err := c.Query(context.Background(), OSVPackage{Name: "pkg", Ecosystem: "npm"}, "1.2.3")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got fixed CVEs=%v", got)
	}
}

func TestGitHubAdvisoryFiltersFixedVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{
			"ghsa_id":"GHSA-xxxx-yyyy-zzzz",
			"cve_id":"CVE-2099-0004",
			"summary":"fixed",
			"severity":"high",
			"published_at":"2099-01-01T00:00:00Z",
			"vulnerabilities":[{"package":{"ecosystem":"pip","name":"django"},"vulnerable_version_range":"< 4.2.20","first_patched_version":"4.2.20"}]
		}]`))
	}))
	defer srv.Close()

	c := NewGitHubAdvisoryClient("")
	c.Endpoint = srv.URL
	got, err := c.Query(context.Background(), GitHubPackage{Ecosystem: "pip", Name: "django"}, "4.2.20")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got fixed advisories=%v", got)
	}
}

func TestMergeCVEEntriesDeduplicatesAndPreservesEPSS(t *testing.T) {
	merged := mergeCVEEntries([]db.CVEEntry{
		{ID: "CVE-1", Source: "osv", Severity: "HIGH"},
		{ID: "CVE-1", Source: "nvd", CVSS: 8.8, EPSS: 0.42, EPSSPercentile: 0.95},
		{ID: "CVE-2", Source: "github"},
	})
	if len(merged) != 2 {
		t.Fatalf("merged=%v", merged)
	}
	if merged[0].ID != "CVE-1" || merged[0].EPSS != 0.42 || !strings.Contains(merged[0].Source, "nvd") {
		t.Fatalf("first=%+v", merged[0])
	}
}
