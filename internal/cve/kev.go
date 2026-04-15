package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/markov/corrivex/internal/db"
)

const kevEndpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVClient fetches the CISA Known Exploited Vulnerabilities catalog.
// Small file (~1.5 MB), no auth. Refresh daily.
type KEVClient struct {
	HTTP *http.Client
}

func NewKEVClient() *KEVClient {
	return &KEVClient{HTTP: &http.Client{Timeout: 60 * time.Second}}
}

type kevFeed struct {
	Title           string        `json:"title"`
	DateReleased    string        `json:"dateReleased"`
	Count           int           `json:"count"`
	Vulnerabilities []kevVulnJSON `json:"vulnerabilities"`
}

type kevVulnJSON struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
}

// Fetch returns the parsed KEV catalog, ready to hand to db.UpsertKEV.
func (c *KEVClient) Fetch(ctx context.Context) ([]db.KEVEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", kevEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Corrivex-CVE-Scanner/1.0")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("kev HTTP %d", resp.StatusCode)
	}
	var feed kevFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}
	out := make([]db.KEVEntry, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		out = append(out, db.KEVEntry{
			CVEID:             v.CVEID,
			Vendor:            v.VendorProject,
			Product:           v.Product,
			VulnerabilityName: v.VulnerabilityName,
			DateAdded:         v.DateAdded,
			ShortDescription:  v.ShortDescription,
		})
	}
	return out, nil
}
