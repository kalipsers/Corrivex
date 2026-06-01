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

func TestSyncDiscoveredLocalInstallersMatchesArchitectureSuffix(t *testing.T) {
	d := testSQLiteDB(t)
	rows, err := d.SyncDiscoveredLocalInstallers("HOST1", []map[string]any{{
		"name": "rustdesk 64", "version": "1.4.6", "path": `\\192.168.100.41\updater\rustdesk-1.4.6-x86_64.msi`,
	}}, []map[string]any{{
		"id": "reg:RustDesk", "name": "RustDesk", "version": "1.4.5.29466336",
	}})
	if err != nil {
		t.Fatalf("sync discovered: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%v", rows)
	}
	if rows[0]["package_id"] != "reg:RustDesk" || rows[0]["available"] != "1.4.6" {
		t.Fatalf("row=%v", rows[0])
	}
}

func TestSyncDiscoveredLocalInstallersMatchesVendorEditionNames(t *testing.T) {
	d := testSQLiteDB(t)
	rows, err := d.SyncDiscoveredLocalInstallers("HOST1", []map[string]any{{
		"name": "RoboForm Enterprise", "version": "9.9.4", "path": `\\192.168.100.41\updater\RoboForm-v9.9.4-Enterprise.msi`,
	}}, []map[string]any{{
		"id": "SiberSystems.RoboForm", "name": "RoboForm 9-7-9-9 (All Users)", "version": "9.7.9.9",
	}})
	if err != nil {
		t.Fatalf("sync discovered: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%v", rows)
	}
	if rows[0]["package_id"] != "SiberSystems.RoboForm" || rows[0]["available"] != "9.9.4" {
		t.Fatalf("row=%v", rows[0])
	}
}

func TestInstalledSoftwareForHostIncludesLocalInstallerCandidate(t *testing.T) {
	d := testSQLiteDB(t)
	host := "HOST1"
	installed := []map[string]any{{
		"id": "reg:RustDesk", "name": "RustDesk", "version": "1.4.5.29466336", "source": "registry",
	}}
	if err := d.SyncInstalledSoftware(host, installed); err != nil {
		t.Fatalf("sync installed: %v", err)
	}
	if _, err := d.SyncDiscoveredLocalInstallers(host, []map[string]any{{
		"name": "rustdesk 64", "version": "1.4.6", "path": `\\192.168.100.41\updater\rustdesk-1.4.6-x86_64.msi`,
	}}, installed); err != nil {
		t.Fatalf("sync discovered: %v", err)
	}
	rows, err := d.InstalledSoftwareForHost(host)
	if err != nil {
		t.Fatalf("installed software: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%+v", rows)
	}
	if rows[0].LocalInstallerID == 0 || rows[0].LocalInstallerVersion != "1.4.6" {
		t.Fatalf("missing local installer candidate: %+v", rows[0])
	}
}

func TestReconcilePackageUpdatesRemovesOutOfBandUpdatedPackage(t *testing.T) {
	pkgs := []map[string]any{{
		"id": "RustDesk.RustDesk", "name": "RustDesk", "version": "1.4.5", "available": "1.4.6",
	}, {
		"id": "Other.Tool", "name": "Other Tool", "version": "1.0.0", "available": "1.1.0",
	}}
	installed := []map[string]any{{
		"id": "RustDesk.RustDesk", "name": "RustDesk", "version": "1.4.6",
	}, {
		"id": "Other.Tool", "name": "Other Tool", "version": "1.0.1",
	}}
	rows := ReconcilePackageUpdates(pkgs, installed)
	if len(rows) != 1 {
		t.Fatalf("rows=%v", rows)
	}
	if rows[0]["id"] != "Other.Tool" || rows[0]["version"] != "1.0.1" {
		t.Fatalf("row=%v", rows[0])
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
