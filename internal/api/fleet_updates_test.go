package api

import "testing"

func TestCollapseFleetUpdateCandidatesGroupsOlderInstalledVersions(t *testing.T) {
	rows := []fleetUpdateHost{
		{
			Hostname:         "HOST1",
			PackageID:        "SiberSystems.RoboForm",
			PackageName:      fleetUpdateDisplayName("SiberSystems.RoboForm", "RoboForm 9-7-9-9 (All Users)"),
			InstalledVersion: "9.7.9.9",
			AvailableVersion: "9.9.4.6",
			Source:           "winget",
			TaskType:         "upgrade_package",
			TaskPackageID:    "SiberSystems.RoboForm",
		},
		{
			Hostname:         "HOST2",
			PackageID:        "SiberSystems.RoboForm",
			PackageName:      fleetUpdateDisplayName("SiberSystems.RoboForm", "RoboForm 9-8-4-4 (All Users)"),
			InstalledVersion: "9.8.4.4",
			AvailableVersion: "9.9.4.6",
			Source:           "winget",
			TaskType:         "upgrade_package",
			TaskPackageID:    "SiberSystems.RoboForm",
		},
	}
	got := collapseFleetUpdateCandidates(rows)
	if len(got) != 2 {
		t.Fatalf("collapsed host candidates=%+v want 2 host rows", got)
	}
	key1 := fleetUpdateProductKey(got[0].PackageID, got[0].PackageName)
	key2 := fleetUpdateProductKey(got[1].PackageID, got[1].PackageName)
	if key1 != key2 || key1 != "roboform" {
		t.Fatalf("keys=%q/%q want roboform", key1, key2)
	}
	if got[0].PackageName != "RoboForm" || got[1].PackageName != "RoboForm" {
		t.Fatalf("names=%q/%q want RoboForm", got[0].PackageName, got[1].PackageName)
	}
}

func TestPreferredFleetUpdateUsesLocalWhenSameOrNewerThanWinget(t *testing.T) {
	rows := []fleetUpdateHost{
		{Hostname: "HOST1", PackageID: "SiberSystems.RoboForm", PackageName: "RoboForm", AvailableVersion: "9.9.4.6", Source: "winget", TaskType: "upgrade_package", TaskPackageID: "SiberSystems.RoboForm"},
		{Hostname: "HOST1", PackageID: "SiberSystems.RoboForm", PackageName: "RoboForm", AvailableVersion: "9.9.5", Source: "local", TaskType: "local_install", TaskPackageID: "42"},
	}
	got := preferredFleetUpdate(rows)
	if got.Source != "local" || got.AvailableVersion != "9.9.5" {
		t.Fatalf("preferred=%+v want local 9.9.5", got)
	}
}

func TestPreferredFleetUpdateKeepsWingetWhenLocalIsOlder(t *testing.T) {
	rows := []fleetUpdateHost{
		{Hostname: "HOST1", PackageID: "SiberSystems.RoboForm", PackageName: "RoboForm", AvailableVersion: "9.9.4.6", Source: "winget", TaskType: "upgrade_package", TaskPackageID: "SiberSystems.RoboForm"},
		{Hostname: "HOST1", PackageID: "SiberSystems.RoboForm", PackageName: "RoboForm", AvailableVersion: "9.9.4", Source: "local", TaskType: "local_install", TaskPackageID: "42"},
	}
	got := preferredFleetUpdate(rows)
	if got.Source != "winget" || got.AvailableVersion != "9.9.4.6" {
		t.Fatalf("preferred=%+v want winget 9.9.4.6", got)
	}
}
