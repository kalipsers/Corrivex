package web

import (
	"strings"
	"testing"
)

func TestDashboardFleetRefreshAllQueuesFullScan(t *testing.T) {
	b, err := fs.ReadFile("templates/dashboard.html.tmpl")
	if err != nil {
		t.Fatalf("read dashboard template: %v", err)
	}
	tpl := string(b)
	for _, want := range []string{
		`data-action="fleet-full-scan"`,
		`Refresh all`,
		`openFleetActionModal('scan')`,
		`taskType = kind === 'scan' ? 'full_scan'`,
	} {
		if !strings.Contains(tpl, want) {
			t.Fatalf("dashboard template missing %q", want)
		}
	}
}

func TestDashboardCascadeWaiterActivelyChecksTaskState(t *testing.T) {
	b, err := fs.ReadFile("templates/dashboard.html.tmpl")
	if err != nil {
		t.Fatalf("read dashboard template: %v", err)
	}
	tpl := string(b)
	for _, want := range []string{
		`waitForCascadeTask(created.task_id, {`,
		`requestCascadeHostSync(host)`,
		`fetchCascadeTaskStatus(taskID, host)`,
		`action=tasks&host=`,
		`cascadeTimeoutMs(h)`,
		`timed out waiting for task result after`,
	} {
		if !strings.Contains(tpl, want) {
			t.Fatalf("dashboard template missing %q", want)
		}
	}
}
