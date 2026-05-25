package db

import (
	"path/filepath"
	"testing"
)

func TestCVEScanStatusRoundTripsDiagnostics(t *testing.T) {
	d, err := Open(Config{Driver: DriverSQLite, Path: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	status := CVEScanStatus{
		PackageID:         "Unmapped.App",
		Version:           "1.2.3",
		Status:            "not_scanned",
		Sources:           "osv,nvd",
		MappingConfidence: "none",
		MappingReason:     "no confident CPE mapping",
		Error:             "unmapped",
	}
	if err := d.UpsertCVEScanStatus(status); err != nil {
		t.Fatalf("upsert status: %v", err)
	}
	rows, err := d.CVEScanStatusForHost("")
	if err != nil {
		t.Fatalf("list status: %v", err)
	}
	if len(rows) != 1 || rows[0].MappingReason != status.MappingReason {
		t.Fatalf("rows=%+v", rows)
	}
}
