package db

import "testing"

func TestSyncDiscoveredLocalInstallersCreatesUpdateRows(t *testing.T) {
	d := testSQLiteDB(t)
	host := "HOST1"
	installed := []map[string]any{{
		"id":      "reg:vendor-app",
		"name":    "Vendor App",
		"version": "1.2.0",
		"source":  "registry",
	}}
	discovered := []map[string]any{{
		"name":           "Vendor App",
		"version":        "1.3.0",
		"path":           `\\fileserver\installers\Vendor-App-1.3.0.msi`,
		"framework_hint": "msi",
		"source":         "smb_scan",
	}}
	rows, err := d.SyncDiscoveredLocalInstallers(host, discovered, installed)
	if err != nil {
		t.Fatalf("sync discovered: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%v", rows)
	}
	if rows[0]["source"] != "local" || rows[0]["package_id"] != "reg:vendor-app" || rows[0]["available"] != "1.3.0" {
		t.Fatalf("row=%v", rows[0])
	}
	if rows[0]["id"] == "" {
		t.Fatalf("missing local installer id: %v", rows[0])
	}
	list, err := d.ListLocalInstallers()
	if err != nil {
		t.Fatalf("list installers: %v", err)
	}
	if len(list) != 1 || list[0].DiscoveredName != "Vendor App" || list[0].DiscoveredVersion != "1.3.0" {
		t.Fatalf("installers=%+v", list)
	}
}

func TestSyncDiscoveredLocalInstallersSkipsOlderVersions(t *testing.T) {
	d := testSQLiteDB(t)
	rows, err := d.SyncDiscoveredLocalInstallers("HOST1", []map[string]any{{
		"name": "Vendor App", "version": "1.1.0", "path": `\\s\i\Vendor-App-1.1.0.exe`,
	}}, []map[string]any{{
		"id": "reg:vendor-app", "name": "Vendor App", "version": "1.2.0",
	}})
	if err != nil {
		t.Fatalf("sync discovered: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows=%v", rows)
	}
}

func TestUNCPathHasRootRequiresBoundary(t *testing.T) {
	if !uncPathHasRoot(`\\server\share\dir\file.msi`, `\\server\share`) {
		t.Fatal("expected root match")
	}
	if uncPathHasRoot(`\\server\share2\file.msi`, `\\server\share`) {
		t.Fatal("share matched share2")
	}
}
