package cve

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/events"
)

// Scanner orchestrates CVE lookups. Runs as a long-lived goroutine started
// from cmd/server/main.go. Thread-safe — a single instance serves the whole
// server process.
type Scanner struct {
	DB      *db.DB
	OSV     *OSVClient
	NVD     *NVDClient
	KEV     *KEVClient
	Broker  *events.Broker // optional, for publishing "cve_scan_done"
	Enabled bool

	// throttle controls the delay between NVD calls. NVD without an API key
	// allows 5 requests per rolling 30 s window — so 6.5 s between requests
	// keeps us clearly under it. With a key the scanner lowers this to 1.5 s.
	throttle time.Duration

	mu      sync.Mutex
	running bool
	lastRun time.Time

	// trigger receives non-blocking pokes to kick the scanner awake.
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
		KEV:      NewKEVClient(),
		Broker:   broker,
		Enabled:  enabled,
		throttle: throttle,
		trigger:  make(chan struct{}, 1),
	}
	// Apply user-supplied winget→CPE overrides from the settings table.
	if raw := database.Setting("cve_winget_cpe_map", ""); raw != "" {
		ApplyUserMap(raw)
	}
	return s
}

// Kick pokes the scanner to wake up now. Non-blocking; if a scan is already
// in progress the poke is a no-op.
func (s *Scanner) Kick() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run is the main loop. Returns when ctx is cancelled. Safe to call exactly
// once per Scanner instance.
func (s *Scanner) Run(ctx context.Context) {
	if !s.Enabled {
		log.Printf("cve: scanner disabled via CVE_SCAN_ENABLED=false")
		return
	}
	// Small initial delay so the server finishes booting + first clients
	// enroll before we pull the catalog.
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	interval := s.cycleInterval()
	log.Printf("cve: scanner running, cycle=%s, nvd-throttle=%s", interval, s.throttle)
	// KEV is fast and independent; refresh it up front so findings can already
	// be enriched on the first scan pass.
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

// cycleInterval reads the configured interval from settings, defaulting to
// 6 hours if unset or invalid.
func (s *Scanner) cycleInterval() time.Duration {
	v := s.DB.Setting("cve_scan_interval_hours", "6")
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		n = 6
	}
	return time.Duration(n) * time.Hour
}

// cacheTTL reads the configured TTL, defaulting to 24 h.
func (s *Scanner) cacheTTL() time.Duration {
	v := s.DB.Setting("cve_cache_ttl_hours", "24")
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		n = 24
	}
	return time.Duration(n) * time.Hour
}

// scanPass queries every (pkg_id, version) that is stale (older than the
// configured TTL, or never scanned). When `force` is true the TTL is
// bypassed and every unique pair is re-queried.
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

	var keys []struct{ PackageID, Version string }
	var err error
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
		cves, src, err := s.query(ctx, k.PackageID, k.Version)
		if err != nil {
			log.Printf("cve: query %s@%s: %v", k.PackageID, k.Version, err)
			continue
		}
		if err := s.DB.UpsertCVECache(k.PackageID, k.Version, src, cves); err != nil {
			log.Printf("cve: upsert %s@%s: %v", k.PackageID, k.Version, err)
			continue
		}
		if len(cves) > 0 {
			hits++
		}
		// Respect NVD rate limit whenever NVD was the source. OSV is fine to
		// hammer but we throttle it lightly to be polite.
		if src == "nvd" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.throttle):
			}
		} else {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
		if (i+1)%50 == 0 {
			log.Printf("cve: progress %d/%d (%d with findings)", i+1, len(keys), hits)
		}
	}
	log.Printf("cve: scan complete — %d packages, %d with findings", len(keys), hits)
	return nil
}

// query runs OSV → NVD in order. Returns the entries plus which source
// produced them ("osv", "nvd", or "none"). Empty entries + "osv" is a valid
// "OSV knows this package and confirmed no known CVEs at this version".
func (s *Scanner) query(ctx context.Context, pkgID, version string) ([]db.CVEEntry, string, error) {
	// Try OSV with ecosystem=Windows/Winget first. OSV doesn't currently
	// ingest winget but does recognise some Windows packages through other
	// feeds, so we try a bare name with no ecosystem too.
	cpe, curated := LookupCPE(pkgID)
	var name string
	if curated {
		name = cpe.Product
	} else {
		name = strings.ToLower(cpe.Product)
	}
	if entries, err := s.OSV.Query(ctx, name, version, ""); err == nil && len(entries) > 0 {
		return entries, "osv", nil
	}
	// Skip NVD for uncurated mappings — the fuzzy guess is too likely to
	// produce false matches on common words like "Git" or "Go". Users can
	// add entries to cve_winget_cpe_map to enable NVD lookups.
	if !curated {
		return nil, "none", nil
	}
	entries, err := s.NVD.Query(ctx, cpe, version)
	if err != nil {
		return nil, "none", err
	}
	if len(entries) > 0 {
		return entries, "nvd", nil
	}
	return nil, "none", nil
}

func (s *Scanner) refreshKEV(ctx context.Context) error {
	entries, err := s.KEV.Fetch(ctx)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	log.Printf("cve: KEV catalog refreshed — %d entries", len(entries))
	return s.DB.UpsertKEV(entries)
}
