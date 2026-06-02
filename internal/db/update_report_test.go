package db

import (
	"testing"
	"time"
)

func TestUpdateReportCombinesHistoryWithMatchingTaskAndTaskOnlyRows(t *testing.T) {
	d := testSQLiteDB(t)
	base := time.Date(2026, 6, 2, 10, 0, 0, 0, time.UTC)

	if _, err := d.sql.Exec(`INSERT INTO installed_software_history
		(hostname, package_id, package_name, old_version, new_version, change_type, detected_at)
		VALUES (?,?,?,?,?,?,?)`,
		"HOST1", "Vendor.App", "Vendor App", "1.0.0", "1.1.0", "updated", base.Add(10*time.Minute)); err != nil {
		t.Fatalf("insert history: %v", err)
	}
	if _, err := d.sql.Exec(`INSERT INTO tasks
		(hostname, type, package_id, package_name, status, created_at, delivered_at, completed_at, result)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		"HOST1", "upgrade_package", "Vendor.App", "Vendor App", "completed",
		base, base.Add(time.Minute), base.Add(5*time.Minute), "updated Vendor.App"); err != nil {
		t.Fatalf("insert package task: %v", err)
	}
	if _, err := d.sql.Exec(`INSERT INTO tasks
		(hostname, type, package_id, package_name, status, created_at, delivered_at, completed_at, result)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		"HOST2", "windows_update_all", "", "", "completed",
		base.Add(20*time.Minute), base.Add(21*time.Minute), base.Add(30*time.Minute), "installed 2 update(s); reboot required"); err != nil {
		t.Fatalf("insert windows task: %v", err)
	}

	rows, err := d.UpdateReport(base.Add(-time.Hour), base.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("update report: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%+v want 2", rows)
	}

	var history, taskOnly *UpdateReportRow
	for i := range rows {
		switch rows[i].Source {
		case "installed_software_history":
			history = &rows[i]
		case "tasks":
			taskOnly = &rows[i]
		}
	}
	if history == nil || history.Method != "winget package upgrade" || history.TaskID == 0 || history.TaskResult != "updated Vendor.App" {
		t.Fatalf("history row=%+v", history)
	}
	if taskOnly == nil || taskOnly.Hostname != "HOST2" || taskOnly.Method != "Windows Update install all" || taskOnly.TaskResult == "" {
		t.Fatalf("task-only row=%+v", taskOnly)
	}
}

func TestUpdateReportHonorsHostScope(t *testing.T) {
	d := testSQLiteDB(t)
	base := time.Date(2026, 6, 2, 10, 0, 0, 0, time.UTC)
	for _, host := range []string{"HOST1", "HOST2"} {
		if _, err := d.sql.Exec(`INSERT INTO installed_software_history
			(hostname, package_id, package_name, old_version, new_version, change_type, detected_at)
			VALUES (?,?,?,?,?,?,?)`,
			host, "Vendor.App", "Vendor App", "1.0.0", "1.1.0", "updated", base); err != nil {
			t.Fatalf("insert history %s: %v", host, err)
		}
	}
	rows, err := d.UpdateReport(base.Add(-time.Hour), base.Add(time.Hour), "HOST2")
	if err != nil {
		t.Fatalf("update report: %v", err)
	}
	if len(rows) != 1 || rows[0].Hostname != "HOST2" {
		t.Fatalf("rows=%+v want HOST2 only", rows)
	}
}
