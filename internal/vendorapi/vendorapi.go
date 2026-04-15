// Package vendorapi polls public version-manifest endpoints for the
// popular winget-targeted packages and caches the results server-side.
// The CVE cascade consumes the cache: when winget can't upgrade a
// package, the server still knows the upstream latest version and can
// label the installed row "out of date" without needing an agent-side
// check.
//
// Every checker returns a single (key, latestVersion) pair. Keys match
// the package_key column on the vendor_versions table and are stable
// across Corrivex versions so the cache survives upgrades.
package vendorapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Result is one vendor-version cache entry ready for UpsertVendorVersion.
type Result struct {
	PackageKey    string // stable canonical key, e.g. "google.chrome", "mozilla.firefox"
	LatestVersion string
	Channel       string // "stable", "esr", "lts", etc.
	Source        string // URL or short provider name — shown in the UI popover
}

// Fetcher runs one network call and returns zero or more Results.
// Fetchers are expected to be short-lived (≤30 s) and safe to call
// concurrently. Errors stop the fetcher but don't abort the scheduler —
// other fetchers keep running.
type Fetcher func(ctx context.Context, client *http.Client) ([]Result, error)

// All returns the full set of built-in fetchers. Admins who want to add
// private vendors can register more via Register(). Only JSON endpoints
// are bundled — HTML-scraping fetchers (7-Zip, WinRAR) intentionally
// omitted because they rot on every vendor redesign.
func All() []Fetcher {
	return append([]Fetcher{
		FetchChrome,
		FetchFirefox,
		FetchFirefoxESR,
		FetchNodeLTS,
		FetchNodeCurrent,
	}, registered...)
}

var registered []Fetcher

// Register attaches a custom fetcher at process startup. Safe to call
// from init() — not goroutine-safe once the scheduler is running.
func Register(f Fetcher) { registered = append(registered, f) }

// ---- built-in fetchers ---------------------------------------------------

// FetchChrome queries Google's official Chrome version-history API.
func FetchChrome(ctx context.Context, client *http.Client) ([]Result, error) {
	const url = "https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions?pageSize=1"
	body, err := getJSON(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Versions []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("chrome decode: %w", err)
	}
	if len(resp.Versions) == 0 {
		return nil, nil
	}
	return []Result{{
		PackageKey:    "google.chrome",
		LatestVersion: resp.Versions[0].Version,
		Channel:       "stable",
		Source:        url,
	}}, nil
}

// FetchFirefox returns the current Mozilla Firefox release.
func FetchFirefox(ctx context.Context, client *http.Client) ([]Result, error) {
	return mozillaVersions(ctx, client, "mozilla.firefox", "LATEST_FIREFOX_VERSION", "stable")
}

// FetchFirefoxESR returns the ESR channel release.
func FetchFirefoxESR(ctx context.Context, client *http.Client) ([]Result, error) {
	return mozillaVersions(ctx, client, "mozilla.firefox.esr", "FIREFOX_ESR", "esr")
}

func mozillaVersions(ctx context.Context, client *http.Client, key, field, channel string) ([]Result, error) {
	const url = "https://product-details.mozilla.org/1.0/firefox_versions.json"
	body, err := getJSON(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("mozilla decode: %w", err)
	}
	v := strings.TrimSpace(m[field])
	if v == "" {
		return nil, nil
	}
	return []Result{{
		PackageKey:    key,
		LatestVersion: v,
		Channel:       channel,
		Source:        url,
	}}, nil
}

// FetchNodeLTS returns the latest Node.js LTS release.
func FetchNodeLTS(ctx context.Context, client *http.Client) ([]Result, error) {
	return nodeVersions(ctx, client, "openjs.node.lts", true)
}

// FetchNodeCurrent returns the latest Node.js current-release line.
func FetchNodeCurrent(ctx context.Context, client *http.Client) ([]Result, error) {
	return nodeVersions(ctx, client, "openjs.node.current", false)
}

type nodeRelease struct {
	Version string `json:"version"` // "v20.11.1"
	LTS     any    `json:"lts"`     // string like "Iron" when LTS, false otherwise
}

func nodeVersions(ctx context.Context, client *http.Client, key string, ltsOnly bool) ([]Result, error) {
	const url = "https://nodejs.org/dist/index.json"
	body, err := getJSON(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var list []nodeRelease
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("node decode: %w", err)
	}
	// Index is sorted newest-first but we don't rely on that.
	sort.SliceStable(list, func(i, j int) bool {
		return versionCompare(strings.TrimPrefix(list[i].Version, "v"),
			strings.TrimPrefix(list[j].Version, "v")) > 0
	})
	for _, r := range list {
		isLTS := false
		if s, ok := r.LTS.(string); ok && s != "" {
			isLTS = true
		}
		if ltsOnly && !isLTS {
			continue
		}
		if !ltsOnly && isLTS {
			// For "current" we want the highest non-LTS tip. Skip LTS rows.
			continue
		}
		channel := "current"
		if isLTS {
			channel = "lts"
		}
		return []Result{{
			PackageKey:    key,
			LatestVersion: strings.TrimPrefix(r.Version, "v"),
			Channel:       channel,
			Source:        url,
		}}, nil
	}
	return nil, nil
}

// ---- GitHub-release-backed fetchers (Notepad++, Git for Windows, VS Code)

// NewGitHubReleaseFetcher builds a Fetcher that looks at the latest
// release of a GitHub repository. GitHub rate-limits anonymous requests
// to 60/hour; the scheduler's 6-hour cadence keeps well under that.
func NewGitHubReleaseFetcher(packageKey, owner, repo, channel string) Fetcher {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	return func(ctx context.Context, client *http.Client) ([]Result, error) {
		body, err := getJSON(ctx, client, url)
		if err != nil {
			return nil, err
		}
		var resp struct {
			TagName    string `json:"tag_name"`
			Name       string `json:"name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("github decode %s/%s: %w", owner, repo, err)
		}
		if resp.Draft || resp.Prerelease {
			return nil, nil
		}
		v := strings.TrimPrefix(resp.TagName, "v")
		if v == "" {
			return nil, nil
		}
		return []Result{{
			PackageKey:    packageKey,
			LatestVersion: v,
			Channel:       channel,
			Source:        url,
		}}, nil
	}
}

// Default GitHub-backed checkers — registered at package init so All()
// picks them up automatically.
func init() {
	Register(NewGitHubReleaseFetcher("microsoft.vscode", "microsoft", "vscode", "stable"))
	Register(NewGitHubReleaseFetcher("git-for-windows", "git-for-windows", "git", "stable"))
	Register(NewGitHubReleaseFetcher("notepad++.notepad++", "notepad-plus-plus", "notepad-plus-plus", "stable"))
}

// ---- helpers ------------------------------------------------------------

func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Corrivex-VendorAPI/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > 2*1024*1024 {
				return nil, fmt.Errorf("%s: response too large", url)
			}
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

// versionCompare does a dotted-numeric compare of two Node-style
// versions. Leading 'v' stripped by the caller. Returns <0, 0, >0.
func versionCompare(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(as) {
			fmt.Sscanf(as[i], "%d", &ai)
		}
		if i < len(bs) {
			fmt.Sscanf(bs[i], "%d", &bi)
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

// DefaultClient is a shared http.Client with a sane timeout. The
// scheduler reuses it for every fetcher.
var DefaultClient = &http.Client{Timeout: 25 * time.Second}
