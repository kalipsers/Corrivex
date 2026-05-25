package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/events"
	"github.com/markov/corrivex/internal/hub"
)

func testServer(t *testing.T) (*Server, *events.Broker, *hub.Hub) {
	t.Helper()
	d, err := db.Open(db.Config{Driver: db.DriverSQLite, Path: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.Migrate(); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	br := events.New()
	h := hub.New()
	return New(d, nil, "", br, h), br, h
}

func TestSyncHostSendsStatusRequestWhenAgentOnline(t *testing.T) {
	s, _, h := testServer(t)
	send := make(chan []byte, 1)
	h.Register(&hub.Conn{Hostname: "HOST1", Send: send})

	req := httptest.NewRequest(http.MethodPost, "/api/?action=sync_host", bytes.NewBufferString(`{"hostname":"host1"}`))
	w := httptest.NewRecorder()
	s.syncHost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "requested" {
		t.Fatalf("status=%q want requested", resp["status"])
	}
	select {
	case raw := <-send:
		var frame map[string]any
		if err := json.Unmarshal(raw, &frame); err != nil {
			t.Fatalf("decode frame: %v", err)
		}
		if frame["type"] != "task_status_request" || frame["request_id"] == "" || frame["include_log_tail"] != true {
			t.Fatalf("frame=%v", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("status request was not sent")
	}
}

func TestTaskSnapshotReconcilesLostDeliveredTask(t *testing.T) {
	s, br, _ := testServer(t)
	sub, unsub := br.Subscribe()
	defer unsub()
	pkgID := "lost.pkg"
	taskID, err := s.DB.CreateTask("HOST1", "upgrade_package", &pkgID, nil, nil)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := s.DB.MarkTaskDelivered(taskID); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}

	raw := []byte(`{"type":"task_snapshot","hostname":"HOST1","active_task":null,"queued_tasks":[],"log_tail":["[12:00:00] old line"]}`)
	s.handleAgentFrame("HOST1", raw, httptest.NewRequest(http.MethodGet, "/", nil))

	tk, _ := s.DB.GetTask(taskID)
	if tk == nil || tk.Status != "failed" {
		t.Fatalf("task=%v want failed", tk)
	}
	if tk.Result == nil || *tk.Result == "" {
		t.Fatalf("result=%v want non-empty interruption result", tk.Result)
	}
	deadline := time.After(time.Second)
	for {
		select {
		case ev := <-sub:
			if ev.Type != "task" {
				continue
			}
			var body map[string]any
			if err := json.Unmarshal(ev.Data, &body); err != nil {
				t.Fatalf("decode event: %v", err)
			}
			if int64(body["task_id"].(float64)) == taskID && body["status"] == "failed" {
				return
			}
		case <-deadline:
			t.Fatal("failed task event was not published")
		}
	}
}
