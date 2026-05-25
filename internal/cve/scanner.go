package cve

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/events"
)

// Scanner orchestrates CVE lookups. Runs as a long-lived goroutine started
// from cmd/server/main.go. Thread-safe: a single instance serves the server.
type Scanner struct {
	DB      *db.DB
	OSV     *OSVClient
	NVD     *NVDClient
	GitHub  *GitHubAdvisoryClient
	EPSS    *EPSSClient
	KEV     *KEVClient
	Broker  *events.Broker
	Enabled bool

	throttle time.Duration

	mu      sync.Mutex
	running bool
	lastRun time.Time
	trigger chan struct{}
}

// New builds a scanner ready to start. Call Run in a goroutine.
func New(database *db.DB, nvdAPIKey string, broker *events.Broker, enabled bool) *Scanner {
	throttle := 7 * time.Second
	if nvdAPIKey != "" {
		throttle = 2 * time.Second
	}
	s := &Scanner{
		DB:       database,
		OSV:      NewOSVClient(),
		NVD:      NewNVDClient(nvdAPIKey),
		GitHub:   NewGitHubAdvisoryClient(os.Getenv("GITHUB_TOKEN")),
		EPSS:     NewEPSSClient(),
		KEV:      NewKEVClient(),
		Broker:   broker,
		Enabled:  enabled,
		throttle: throttle,
		trigger:  make(chan struct{}, 1),
	}
	ApplyUserMap(database.Setting("cve_winget_cpe_map", ""))
	return s
}

// Kick pokes the scanner to wake up now. Non-blocking.
func (s *Scanner) Kick() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run is the main loop. Returns when ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	if !s.Enabled {
		log.Printf("cve: scanner disabled via CVE_SCAN_ENABLED=false")
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	interval := s.cycleInterval()
	log.Printf("cve: scanner running, cycle=%s, nvd-throttle=%s", interval, s.throttle)
	if err := s.refreshKEV(ctx); err != nil {
		log.Printf("cve: initial KEV refresh failed: %v", err)
	}
	if err := s.scanPass(ctx, false); err != nil {
		log.Printf("cve: initial scan failed: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	kevTicker := time.NewTicker(24 * time.Hour)
	defer kevTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scanPass(ctx, false); err != nil {
				log.Printf("cve: scan failed: %v", err)
			}
		case <-kevTicker.C:
			if err := s.refreshKEV(ctx); err != nil {
				log.Printf("cve: KEV refresh failed: %v", err)
			}
		case <-s.trigger:
			if err := s.scanPass(ctx, true); err != nil {
				log.Printf("cve: manual rescan failed: %v", err)
			}
		}
	}
}

func (s *Scanner) cycleInterval() time.Duration {
	v := s.DB.Setting("cve_scan_interval_hours", "6")
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		n = 6
	}
	return time.Duration(n) * time.Hour
}

func (s *Scanner) cacheTTL() time.Duration {
	v := s.DB.Setting("cve_cache_ttl_hours", "24")
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		n = 24
	}
	return time.Duration(n) * time.Hour
}

func (s *Scanner) scanPass(ctx context.Context, force bool) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		log.Printf("cve: scan already in progress, skipping")
		return nil
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.lastRun = time.Now()
		s.mu.Unlock()
		if s.Broker != nil {
			s.Broker.Publish("cve_scan_done", map[string]any{"at": time.Now().UTC().Format(time.RFC3339)})
		}
	}()

	var (
		keys []db.CVEScanKey
		err  error
	)
	if force {
		keys, err = s.DB.UniquePackageVersions()
	} else {
		keys, err = s.DB.StaleCVECacheKeys(s.cacheTTL())
	}
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		log.Printf("cve: nothing to scan (all fresh)")
		return nil
	}

	log.Printf("cve: scanning %d unique package-version pairs", len(keys))
	hits := 0
	for i, k := range keys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !hasScannableVersion(k.Version) {
			_ = s.DB.UpsertCVEScanStatus(db.CVEScanStatus{
				PackageID: k.PackageID,
				Version:   k.Version,
				Status:    "not_scanned",
				Error:     "unscannable version",
			})
			continue
		}

		cves, status, err := s.query(ctx, k)
		if err != nil {
			log.Printf("cve: query %s@%s: %v", k.PackageID, k.Version, err)
			status.Status = "error"
			status.Error = err.Error()
			_ = s.DB.UpsertCVEScanStatus(status)
			continue
		}
		src := firstNonEmpty(status.Sources, "none")
		if err := s.DB.UpsertCVECache(k.PackageID, k.Version, src, cves); err != nil {
			log.Printf("cve: upsert %s@%s: %v", k.PackageID, k.Version, err)
			continue
		}
		if err := s.DB.UpsertCVEScanStatus(status); err != nil {
			log.Printf("cve: status %s@%s: %v", k.PackageID, k.Version, err)
		}
		if len(cves) > 0 {
			hits++
		}

		delay := 200 * time.Millisecond
		if strings.Contains(src, "nvd") {
			delay = s.throttle
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if (i+1)%50 == 0 {
			log.Printf("cve: progress %d/%d (%d with findings)", i+1, len(keys), hits)
		}
	}
	log.Printf("cve: scan complete: %d packages, %d with findings", len(keys), hits)
	return nil
}

func (s *Scanner) query(ctx context.Context, k db.CVEScanKey) ([]db.CVEEntry, db.CVEScanStatus, error) {
	status := db.CVEScanStatus{PackageID: k.PackageID, Version: k.Version, Status: "scanned"}
	ApplyUserMap(s.DB.Setting("cve_winget_cpe_map", ""))

	nvdOn := s.sourceEnabled("cve_source_nvd", true)
	osvOn := s.sourceEnabled("cve_source_osv", true)
	githubOn := s.sourceEnabled("cve_source_github", true)
	epssOn := s.sourceEnabled("cve_source_epss", true)
	minConfidence := strings.ToLower(strings.TrimSpace(s.DB.Setting("cve_min_mapping_confidence", "high")))
	if minConfidence == "" {
		minConfidence = "high"
	}

	var (
		lists   [][]db.CVEEntry
		sources []string
		cpe     CPE
		mapping *db.CVEPackageMapping
	)

	if nvdOn {
		m, err := s.resolveCPE(ctx, k)
		if err != nil {
			return nil, status, err
		}
		mapping = m
		if mapping != nil {
			status.MappingConfidence = mapping.Confidence
			status.MappingReason = mapping.Reason
			cpe = CPE{Vendor: mapping.CPEVendor, Product: mapping.CPEProduct}
		}
	}

	if osvOn {
		entries, err := s.queryOSV(ctx, k, cpe)
		if err != nil {
			return nil, status, err
		}
		lists = append(lists, entries)
		sources = append(sources, "osv")
	}

	if nvdOn && mapping != nil && confidenceAtLeast(mapping.Confidence, minConfidence) {
		entries, err := s.NVD.Query(ctx, cpe, k.Version, mapping.Confidence)
		if err != nil {
			return nil, status, err
		}
		lists = append(lists, entries)
		sources = append(sources, "nvd")
	} else if nvdOn && mapping == nil {
		status.Status = "not_scanned"
		status.Error = "unmapped for NVD"
	} else if nvdOn && mapping != nil {
		status.MappingReason = strings.TrimSpace(status.MappingReason + "; below minimum confidence")
		status.Status = "not_scanned"
		status.Error = "NVD mapping below minimum confidence"
	}

	if githubOn {
		entries, err := s.queryGitHub(ctx, k)
		if err != nil {
			return nil, status, err
		}
		lists = append(lists, entries)
		sources = append(sources, "github")
	}

	entries := mergeCVEEntries(lists...)
	if epssOn && len(entries) > 0 {
		if err := s.enrichEPSS(ctx, entries); err != nil {
			log.Printf("cve: epss enrichment failed for %s@%s: %v", k.PackageID, k.Version, err)
		} else {
			sources = append(sources, "epss")
		}
	}

	status.Sources = strings.Join(uniqueStrings(sources), ",")
	if status.Status == "not_scanned" && len(sources) > 0 {
		status.Status = "scanned"
		status.Error = ""
	}
	if status.Sources == "" && status.Status == "scanned" {
		status.Status = "not_scanned"
		status.Error = "all CVE sources disabled"
	}
	return entries, status, nil
}

func (s *Scanner) resolveCPE(ctx context.Context, k db.CVEScanKey) (*db.CVEPackageMapping, error) {
	if cpe, ok := LookupCPE(k.PackageID); ok {
		m := db.CVEPackageMapping{
			PackageID:  k.PackageID,
			CPEVendor:  cpe.Vendor,
			CPEProduct: cpe.Product,
			Confidence: "high",
			Reason:     "curated winget mapping",
			Source:     "curated",
		}
		_ = s.DB.UpsertCVEPackageMapping(m)
		return &m, nil
	}
	if cached, err := s.DB.GetCVEPackageMapping(k.PackageID); err == nil && cached != nil {
		return cached, nil
	} else if err != nil {
		return nil, err
	}
	m, err := s.NVD.DiscoverCPE(ctx, k.PackageID, k.PackageName)
	if err != nil {
		return nil, err
	}
	if m.CPE.Vendor == "" || m.CPE.Product == "" || m.Confidence == "none" {
		if m.PackageID != "" {
			_ = s.DB.UpsertCVEPackageMapping(db.CVEPackageMapping{
				PackageID:  k.PackageID,
				Confidence: firstNonEmpty(m.Confidence, "none"),
				Reason:     m.Reason,
				Source:     firstNonEmpty(m.Source, "nvd_cpe"),
			})
		}
		return nil, nil
	}
	row := db.CVEPackageMapping{
		PackageID:  k.PackageID,
		CPEVendor:  m.CPE.Vendor,
		CPEProduct: m.CPE.Product,
		CPEName:    m.CPEName,
		Title:      m.Title,
		Confidence: m.Confidence,
		Reason:     m.Reason,
		Source:     m.Source,
	}
	if err := s.DB.UpsertCVEPackageMapping(row); err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *Scanner) queryOSV(ctx context.Context, k db.CVEScanKey, cpe CPE) ([]db.CVEEntry, error) {
	pkgs := osvPackagesFor(k, cpe)
	var lists [][]db.CVEEntry
	for _, pkg := range pkgs {
		entries, err := s.OSV.Query(ctx, pkg, k.Version)
		if err != nil {
			return nil, err
		}
		lists = append(lists, entries)
	}
	return mergeCVEEntries(lists...), nil
}

func (s *Scanner) queryGitHub(ctx context.Context, k db.CVEScanKey) ([]db.CVEEntry, error) {
	pkgs := githubPackagesFor(k)
	var lists [][]db.CVEEntry
	for _, pkg := range pkgs {
		entries, err := s.GitHub.Query(ctx, pkg, k.Version)
		if err != nil {
			return nil, err
		}
		lists = append(lists, entries)
	}
	return mergeCVEEntries(lists...), nil
}

func (s *Scanner) enrichEPSS(ctx context.Context, entries []db.CVEEntry) error {
	var ids []string
	for _, e := range entries {
		if strings.HasPrefix(strings.ToUpper(e.ID), "CVE-") {
			ids = append(ids, e.ID)
		}
	}
	scores, err := s.EPSS.Query(ctx, ids)
	if err != nil {
		return err
	}
	for i := range entries {
		if sc, ok := scores[entries[i].ID]; ok {
			entries[i].EPSS = sc.EPSS
			entries[i].EPSSPercentile = sc.Percentile
		}
	}
	return nil
}

func (s *Scanner) sourceEnabled(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(s.DB.Setting(key, strconv.FormatBool(def))))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func hasScannableVersion(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			return true
		}
	}
	return false
}

func confidenceAtLeast(got, min string) bool {
	return confidenceRank(got) >= confidenceRank(min)
}

func confidenceRank(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func osvPackagesFor(k db.CVEScanKey, cpe CPE) []OSVPackage {
	seen := map[string]bool{}
	add := func(out *[]OSVPackage, p OSVPackage) {
		if p.Name == "" && p.PURL == "" {
			return
		}
		key := p.Ecosystem + "\x00" + p.Name + "\x00" + p.PURL
		if seen[key] {
			return
		}
		seen[key] = true
		*out = append(*out, p)
	}
	var out []OSVPackage
	if p, ok := knownOSVPackage(k.PackageID); ok {
		add(&out, p)
	}
	if cpe.Product != "" {
		add(&out, OSVPackage{Name: cpe.Product})
	}
	name := strings.TrimSpace(k.PackageName)
	if name != "" {
		add(&out, OSVPackage{Name: strings.ToLower(name)})
	}
	return out
}

func knownOSVPackage(packageID string) (OSVPackage, bool) {
	switch packageID {
	case "pnpm.pnpm":
		return OSVPackage{Name: "pnpm", Ecosystem: "npm", PURL: "pkg:npm/pnpm"}, true
	case "Yarn.Yarn":
		return OSVPackage{Name: "yarn", Ecosystem: "npm", PURL: "pkg:npm/yarn"}, true
	default:
		return OSVPackage{}, false
	}
}

func githubPackagesFor(k db.CVEScanKey) []GitHubPackage {
	switch k.PackageID {
	default:
		return nil
	}
}

func (s *Scanner) refreshKEV(ctx context.Context) error {
	entries, err := s.KEV.Fetch(ctx)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	log.Printf("cve: KEV catalog refreshed: %d entries", len(entries))
	return s.DB.UpsertKEV(entries)
}
