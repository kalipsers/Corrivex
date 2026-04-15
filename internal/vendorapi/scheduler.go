package vendorapi

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/markov/corrivex/internal/db"
)

// Scheduler runs Fetchers on a timer and upserts results into the
// vendor_versions table. One instance is spawned from cmd/server/main.go
// when VENDOR_VERSION_ENABLED is true.
type Scheduler struct {
	DB       *db.DB
	Fetchers []Fetcher
}

// NewDefault wires the scheduler with every built-in fetcher.
func NewDefault(database *db.DB) *Scheduler {
	return &Scheduler{DB: database, Fetchers: All()}
}

// Run loops until ctx is cancelled. One cycle runs every
// `vendor_version_interval_hours` hours (default 6). A 20-second
// initial delay lets the server finish boot before any outbound
// calls go out.
func (s *Scheduler) Run(ctx context.Context) {
	enabled := s.DB.Setting("vendor_version_enabled", "true")
	if !truthy(enabled) {
		log.Printf("vendorapi: disabled (vendor_version_enabled=false)")
		return
	}
	interval := s.interval()
	log.Printf("vendorapi: running; cycle=%s, fetchers=%d", interval, len(s.Fetchers))

	select {
	case <-time.After(20 * time.Second):
	case <-ctx.Done():
		return
	}
	s.runOnce(ctx)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Scheduler) interval() time.Duration {
	v := s.DB.Setting("vendor_version_interval_hours", "6")
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		n = 6
	}
	return time.Duration(n) * time.Hour
}

func (s *Scheduler) runOnce(ctx context.Context) {
	total := 0
	for _, f := range s.Fetchers {
		results, err := f(ctx, DefaultClient)
		if err != nil {
			log.Printf("vendorapi: fetcher error: %v", err)
			continue
		}
		for _, r := range results {
			if err := s.DB.UpsertVendorVersion(r.PackageKey, r.LatestVersion, r.Channel, r.Source); err != nil {
				log.Printf("vendorapi: upsert %s: %v", r.PackageKey, err)
				continue
			}
			total++
		}
	}
	log.Printf("vendorapi: cycle complete — %d entries updated", total)
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
