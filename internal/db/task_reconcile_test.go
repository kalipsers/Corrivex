package db

import (
	"path/filepath"
	"strings"
	"testing"
)

func testSQLiteDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(Config{Driver: DriverSQLite, Path: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.Migrate(); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return d
}

func TestFailDeliveredTasksNotInSnapshotMarksOnlyMissingTasksFailed(t *testing.T) {
	d := testSQLiteDB(t)
	host := "HOST1"
	keepID, err := d.CreateTask(host, "upgrade_package", strp("keep.pkg"), strp("Keep"), nil)
	if err != nil {
		t.Fatalf("create keep task: %v", err)
	}
	failID, err := d.CreateTask(host, "upgrade_package", strp("lost.pkg"), strp("Lost"), nil)
	if err != nil {
		t.Fatalf("create lost task: %v", err)
	}
	if err := d.MarkTaskDelivered(keepID); err != nil {
		t.Fatalf("mark keep delivered: %v", err)
	}
	if err := d.MarkTaskDelivered(failID); err != nil {
		t.Fatalf("mark lost delivered: %v", err)
	}

	failed, err := d.FailDeliveredTasksNotInSnapshot(host, map[int64]bool{keepID: true}, "interrupted: agent reports task is not active after reconnect")
	if err != nil {
		t.Fatalf("fail stale delivered: %v", err)
	}

	if len(failed) != 1 || failed[0].ID != failID {
		t.Fatalf("failed=%v want only task %d", failed, failID)
	}
	kept, _ := d.GetTask(keepID)
	lost, _ := d.GetTask(failID)
	if kept == nil || kept.Status != "delivered" {
		t.Fatalf("kept status=%v want delivered", kept)
	}
	if lost == nil || lost.Status != "failed" {
		t.Fatalf("lost status=%v want failed", lost)
	}
	if lost.Result == nil || !strings.Contains(*lost.Result, "interrupted") {
		t.Fatalf("lost result=%v", lost.Result)
	}
}

func strp(s string) *string { return &s }
