package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type EPSSClient struct {
	HTTP     *http.Client
	Endpoint string
}

func NewEPSSClient() *EPSSClient {
	return &EPSSClient{HTTP: &http.Client{Timeout: 15 * time.Second}, Endpoint: "https://api.first.org/data/v1/epss"}
}

type EPSSScore struct {
	EPSS       float64
	Percentile float64
}

func (c *EPSSClient) Query(ctx context.Context, cveIDs []string) (map[string]EPSSScore, error) {
	if len(cveIDs) == 0 {
		return map[string]EPSSScore{}, nil
	}
	q := url.Values{}
	q.Set("cve", strings.Join(cveIDs, ","))
	req, err := http.NewRequestWithContext(ctx, "GET", c.Endpoint+"?"+q.Encode(), nil)
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
		return nil, fmt.Errorf("epss HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	out := map[string]EPSSScore{}
	for _, row := range body.Data {
		out[row.CVE] = EPSSScore{EPSS: parseFloatString(row.EPSS), Percentile: parseFloatString(row.Percentile)}
	}
	return out, nil
}
