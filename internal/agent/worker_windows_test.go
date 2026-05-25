//go:build windows

package agent

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/markov/corrivex/internal/winget"
)

func TestTaskWorkerRunsWingetTasksSequentially(t *testing.T) {
	r := New(Config{}, t.TempDir(), nil)
	r.runWingetTask = func(ctx context.Context, t TaskRequest, timeout time.Duration, logf func(string, ...any)) (string, int) {
		time.Sleep(25 * time.Millisecond)
		return t.PackageID, 0
	}
	r.postMutationScan = func(int) {}
	var mu sync.Mutex
	var completed []string
	r.reportTaskResult = func(t TaskRequest, result string) {
		mu.Lock()
		defer mu.Unlock()
		completed = append(completed, fmt.Sprintf("%d:%s", t.ID, result))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.startTaskWorker(ctx)
	r.enqueueTask(TaskRequest{ID: 1, Type: "upgrade_package", PackageID: "A"})
	r.enqueueTask(TaskRequest{ID: 2, Type: "upgrade_package", PackageID: "B"})
	r.waitTaskQueueIdle(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	want := []string{"1:completed", "2:completed"}
	if !reflect.DeepEqual(completed, want) {
		t.Fatalf("completed=%v want=%v", completed, want)
	}
}

func TestRunUpgradeAllContinuesAfterPackageTimeout(t *testing.T) {
	r := New(Config{}, t.TempDir(), nil)
	r.listUpgrades = func() ([]winget.Package, error) {
		return []winget.Package{
			{ID: "slow.pkg", Name: "Slow"},
			{ID: "fast.pkg", Name: "Fast"},
		}, nil
	}
	var seen []string
	r.runWingetTask = func(ctx context.Context, t TaskRequest, timeout time.Duration, logf func(string, ...any)) (string, int) {
		seen = append(seen, t.PackageID)
		if t.PackageID == "slow.pkg" {
			return "timeout_killed", winget.TimeoutExitCode
		}
		return "completed", 0
	}
	r.postMutationScan = func(int) {}

	out, code := r.runUpgradeAllSequential(context.Background(), TaskRequest{ID: 99, Type: "upgrade_all"}, 20*time.Minute)

	if code != winget.TimeoutExitCode {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if !reflect.DeepEqual(seen, []string{"slow.pkg", "fast.pkg"}) {
		t.Fatalf("seen=%v", seen)
	}
	if !strings.Contains(out, "completed=1 failed=0 timeout=1 total=2") {
		t.Fatalf("summary=%q", out)
	}
}

func TestParseWingetPackageTimeout(t *testing.T) {
	if got := parseWingetPackageTimeout(nil); got != 20*time.Minute {
		t.Fatalf("default timeout=%s", got)
	}
	if got := parseWingetPackageTimeout(map[string]string{"winget_package_timeout_minutes": "7"}); got != 7*time.Minute {
		t.Fatalf("configured timeout=%s", got)
	}
	if got := parseWingetPackageTimeout(map[string]string{"winget_package_timeout_minutes": "0"}); got != 20*time.Minute {
		t.Fatalf("invalid timeout=%s", got)
	}
}

func TestTaskSnapshotTracksQueuedActiveAndLogTail(t *testing.T) {
	r := New(Config{}, t.TempDir(), nil)
	started := make(chan struct{})
	release := make(chan struct{})
	r.runWingetTask = func(ctx context.Context, t TaskRequest, timeout time.Duration, logf func(string, ...any)) (string, int) {
		close(started)
		<-release
		return "completed", 0
	}
	r.postMutationScan = func(int) {}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.startTaskWorker(ctx)
	r.enqueueTask(TaskRequest{ID: 1, Type: "upgrade_package", PackageID: "A"})
	r.enqueueTask(TaskRequest{ID: 2, Type: "upgrade_package", PackageID: "B"})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first task did not start")
	}
	r.log("snapshot test line")

	snap := r.taskSnapshot("req-1", true)
	if snap.RequestID != "req-1" {
		t.Fatalf("request id=%q", snap.RequestID)
	}
	if snap.ActiveTask == nil || snap.ActiveTask.ID != 1 {
		t.Fatalf("active=%v want task 1", snap.ActiveTask)
	}
	if len(snap.QueuedTasks) != 1 || snap.QueuedTasks[0].ID != 2 {
		t.Fatalf("queued=%v want task 2", snap.QueuedTasks)
	}
	if len(snap.LogTail) == 0 || !strings.Contains(snap.LogTail[len(snap.LogTail)-1], "snapshot test line") {
		t.Fatalf("log tail=%v", snap.LogTail)
	}

	snapAgain := r.taskSnapshot("req-2", true)
	if len(snapAgain.LogTail) == 0 || !strings.Contains(snapAgain.LogTail[len(snapAgain.LogTail)-1], "snapshot test line") {
		t.Fatalf("second log tail=%v; want non-draining tail", snapAgain.LogTail)
	}
	close(release)
	r.waitTaskQueueIdle(2 * time.Second)
}
