//go:build windows

// Package agent is the Corrivex Windows Service agent runtime.
package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/markov/corrivex/internal/version"
	"github.com/markov/corrivex/internal/winget"
	"github.com/markov/corrivex/internal/winupdate"
)

// Config describes agent behaviour. Written to config.json next to the binary.
type Config struct {
	Server      string `json:"server"`
	CheckMin    int    `json:"check_min"`
	ScanHrs     int    `json:"scan_hrs"`
	ServiceName string `json:"service_name"`
	APISecret   string `json:"api_secret,omitempty"`
	// AgentToken is the per-agent secret obtained on first enrollment.
	// Sent as the X-Corrivex-Token header on every subsequent request.
	AgentToken string `json:"agent_token,omitempty"`
}

// Runtime holds shared agent state + logger.
type Runtime struct {
	Cfg     Config
	DataDir string
	Logf    func(format string, args ...any)
	http    *http.Client
	mu      sync.Mutex
	logBuf  []string
	selfSha string

	// wsSend is the per-session outbound queue. Non-nil while a session is
	// live. log() tees every line into it as {type:"log",line:...} so the
	// server can stream to the dashboard in real time.
	wsSend chan []byte
}

func New(cfg Config, dataDir string, logf func(string, ...any)) *Runtime {
	r := &Runtime{
		Cfg: cfg, DataDir: dataDir, Logf: logf,
		http: &http.Client{Timeout: 60 * time.Second},
	}
	r.selfSha = selfSHA256()
	return r
}

func (r *Runtime) configPath() string { return filepath.Join(r.DataDir, "config.json") }

// saveConfig persists Cfg back to disk. Called whenever we receive (or
// rotate) the agent token from the server.
func (r *Runtime) saveConfig() {
	b, err := json.MarshalIndent(r.Cfg, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(r.configPath(), b, 0o644)
}

func (r *Runtime) log(format string, args ...any) {
	raw := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + raw
	r.mu.Lock()
	r.logBuf = append(r.logBuf, line)
	if len(r.logBuf) > 400 {
		r.logBuf = r.logBuf[len(r.logBuf)-400:]
	}
	sendCh := r.wsSend
	r.mu.Unlock()
	if r.Logf != nil {
		r.Logf("%s", line)
	}
	// Best-effort stream to server. Dropped silently if the session queue is
	// full or not active.
	if sendCh != nil {
		if b, err := json.Marshal(map[string]string{"type": "log", "line": raw}); err == nil {
			select {
			case sendCh <- b:
			default:
			}
		}
	}
}

func (r *Runtime) drainLog() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := strings.Join(r.logBuf, "\n")
	r.logBuf = nil
	return s
}

// Run keeps a WebSocket session open to the server for the duration of the
// service. Inside a session:
//   - we send a `hello` frame, authenticate with the TOFU token,
//   - stream log lines live,
//   - send full_report whenever the scan timer fires (and on session start),
//   - handle pushed tasks immediately.
//
// On any session error we reconnect with exponential backoff. The only timer
// left is the periodic full-scan (default 24h).
func (r *Runtime) Run(ctx context.Context) {
	r.log("Corrivex agent v%s starting (server=%s, scan=%dh, self=%s)",
		version.Version, r.Cfg.Server, r.Cfg.ScanHrs, shortHash(r.selfSha))
	cleanupStaleBinary()
	r.safe(func() { r.checkSelfUpdate() })

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := r.runSession(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			r.log("session ended: %v (retry in %s)", err, backoff)
		} else {
			r.log("session ended cleanly (retry in %s)", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
		// Before reconnecting, take the chance to self-update.
		r.safe(func() { r.checkSelfUpdate() })
	}
}

// runSession opens one WebSocket and processes frames until it fails.
func (r *Runtime) runSession(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	u := buildWSURL(r.Cfg.Server)
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPClient: r.http,
	})
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}
	defer c.CloseNow()
	c.SetReadLimit(8 << 20)

	// Send hello.
	hostname := mustHost()
	hello := map[string]any{
		"type":          "hello",
		"hostname":      hostname,
		"token":         r.Cfg.AgentToken,
		"domain":        detectDomain(),
		"agent_sha256":  r.selfSha,
		"agent_version": version.Version,
	}
	if b, err := json.Marshal(hello); err != nil || c.Write(ctx, websocket.MessageText, b) != nil {
		return fmt.Errorf("hello send")
	}

	// Expect hello_ok with possibly-new token.
	readCtx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	_, helloResp, err := c.Read(readCtx)
	rcancel()
	if err != nil {
		return fmt.Errorf("hello recv: %w", err)
	}
	var hr struct {
		Type        string `json:"type"`
		AgentToken  string `json:"agent_token"`
		AgentSHA256 string `json:"agent_sha256"`
	}
	if err := json.Unmarshal(helloResp, &hr); err != nil || hr.Type != "hello_ok" {
		return fmt.Errorf("bad hello response")
	}
	if hr.AgentToken != "" && hr.AgentToken != r.Cfg.AgentToken {
		r.log("adopted agent token %s", shortHash(hr.AgentToken))
		r.Cfg.AgentToken = hr.AgentToken
		r.saveConfig()
	}
	if hr.AgentSHA256 != "" && hr.AgentSHA256 != r.selfSha {
		r.log("server has a newer agent build; triggering self-update")
		// non-blocking: try now; reconnect loop will try again next tick
		go r.safe(func() { r.checkSelfUpdate() })
	}

	// Wire up the outbound queue so log() can stream lines.
	sendCh := make(chan []byte, 128)
	r.mu.Lock()
	r.wsSend = sendCh
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.wsSend = nil
		r.mu.Unlock()
	}()

	// Writer goroutine.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-sendCh:
				if !ok {
					return
				}
				wc, wcancel := context.WithTimeout(ctx, 10*time.Second)
				err := c.Write(wc, websocket.MessageText, msg)
				wcancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// Ensure winget is present (installs if missing), then first full scan.
	// ensureWinget is idempotent so re-running it at every scan tick is cheap.
	go func() {
		r.safe(func() { r.ensureWinget() })
		r.safe(func() { r.fullScanWS(ctx) })
	}()
	scanEvery := time.Duration(maxI(r.Cfg.ScanHrs, 1)) * time.Hour
	scanTicker := time.NewTicker(scanEvery)
	defer scanTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-scanTicker.C:
				r.safe(func() { r.checkSelfUpdate() })
				r.safe(func() { r.ensureWinget() })
				r.safe(func() { r.fullScanWS(ctx) })
			}
		}
	}()

	// Reader loop.
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return err
		}
		var env struct{ Type string `json:"type"` }
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		switch env.Type {
		case "ping":
			select {
			case sendCh <- []byte(`{"type":"pong"}`):
			default:
			}
		case "task":
			var m struct {
				Task TaskRequest `json:"task"`
			}
			if err := json.Unmarshal(data, &m); err == nil {
				go r.safe(func() { r.RunTasks([]TaskRequest{m.Task}) })
			}
		}
	}
}

// buildWSURL converts http(s)://host → ws(s)://host/api/?action=agent_ws.
func buildWSURL(server string) string {
	s := strings.TrimRight(server, "/")
	switch {
	case strings.HasPrefix(s, "https://"):
		s = "wss://" + strings.TrimPrefix(s, "https://")
	case strings.HasPrefix(s, "http://"):
		s = "ws://" + strings.TrimPrefix(s, "http://")
	}
	return s + "/api/?action=agent_ws"
}

func (r *Runtime) safe(fn func()) {
	defer func() {
		if p := recover(); p != nil {
			r.log("panic: %v", p)
		}
	}()
	fn()
}

// -- server comms ----------------------------------------------------------

type apiResp struct {
	Status      string        `json:"status"`
	Error       string        `json:"error"`
	Tasks       []TaskRequest `json:"tasks"`
	AgentToken  string        `json:"agent_token,omitempty"`
	AgentSHA256 string        `json:"agent_sha256,omitempty"`
}

type TaskRequest struct {
	ID             int64  `json:"id"`
	Type           string `json:"type"`
	PackageID      string `json:"package_id"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}

func (r *Runtime) post(action string, body any) (*apiResp, error) {
	b, _ := json.Marshal(body)
	u := strings.TrimRight(r.Cfg.Server, "/") + "/api/?action=" + action
	req, _ := http.NewRequest("POST", u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if r.Cfg.APISecret != "" {
		req.Header.Set("X-API-Secret", r.Cfg.APISecret)
	}
	if r.Cfg.AgentToken != "" {
		req.Header.Set("X-Corrivex-Token", r.Cfg.AgentToken)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var ar apiResp
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("bad response %d: %s", resp.StatusCode, string(data))
	}
	// Adopt token issued by the server on first enrollment (TOFU).
	if ar.AgentToken != "" && ar.AgentToken != r.Cfg.AgentToken {
		r.log("adopted agent token %s (was %s)", shortHash(ar.AgentToken), shortHash(r.Cfg.AgentToken))
		r.Cfg.AgentToken = ar.AgentToken
		r.saveConfig()
	}
	if ar.Error != "" {
		return &ar, fmt.Errorf("server: %s", ar.Error)
	}
	return &ar, nil
}

// sendWS marshals and queues a frame. Returns false if no session is active.
func (r *Runtime) sendWS(msg any) bool {
	r.mu.Lock()
	ch := r.wsSend
	r.mu.Unlock()
	if ch == nil {
		return false
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	select {
	case ch <- b:
		return true
	default:
		return false
	}
}

// fullScanWS collects the same payload as FullScan() but sends it over the
// active WebSocket. Used from within a session.
func (r *Runtime) fullScanWS(ctx context.Context) {
	hostname, _ := os.Hostname()
	domain := detectDomain()
	user := os.Getenv("USERNAME")
	osv := detectOSVersion()
	r.log("full scan: host=%s domain=%s", hostname, domain)

	pkgs, err := winget.ListUpgrades()
	if err != nil {
		r.log("winget upgrades list failed: %v", err)
	}
	// Full inventory of installed software for the per-host history view.
	installed, err := winget.ListInstalled()
	if err != nil {
		r.log("winget list (installed) failed: %v", err)
	} else {
		r.log("installed packages enumerated: %d", len(installed))
	}
	users := detectLocalUsers()
	admins := detectLocalAdmins()

	// Windows Update scan — best-effort, 2-minute timeout. A missing or
	// disabled WU service should not block winget inventory.
	wuCtx, wuCancel := context.WithTimeout(ctx, 2*time.Minute)
	wuList, wuErr := winupdate.List(wuCtx)
	wuCancel()
	if wuErr != nil {
		r.log("windows update scan failed: %v", wuErr)
	} else {
		r.log("windows updates pending: %d", len(wuList))
	}

	body := map[string]any{
		"type":               "report",
		"action":             "full_report",
		"hostname":           hostname,
		"domain":             domain,
		"os_version":         osv,
		"username":           user,
		"timestamp":          time.Now().Format("2006-01-02 15:04:05"),
		"users":              users,
		"local_admins":       admins,
		"packages":           pkgs,
		"installed_software": installed,
		"windows_updates":    wuList,
		"update_count":       len(pkgs),
	}
	if !r.sendWS(body) {
		// Fallback: HTTP report (used only if the WS went away right now).
		r.FullScan()
	}
}

// FullScan reports system info + pending updates, then runs any returned tasks.
func (r *Runtime) FullScan() {
	hostname, _ := os.Hostname()
	domain := detectDomain()
	user := os.Getenv("USERNAME")
	osv := detectOSVersion()
	r.log("full scan: host=%s domain=%s os=%q", hostname, domain, osv)

	pkgs, err := winget.ListUpgrades()
	if err != nil {
		r.log("winget upgrades list failed: %v", err)
	}
	installed, err := winget.ListInstalled()
	if err != nil {
		r.log("winget list (installed) failed: %v", err)
	}
	users := detectLocalUsers()
	admins := detectLocalAdmins()

	body := map[string]any{
		"action":             "full_report",
		"hostname":           hostname,
		"domain":             domain,
		"os_version":         osv,
		"username":           user,
		"timestamp":          time.Now().Format("2006-01-02 15:04:05"),
		"users":              users,
		"local_admins":       admins,
		"packages":           pkgs,
		"installed_software": installed,
		"update_count":       len(pkgs),
		"agent_log":          r.drainLog(),
	}

	resp, err := r.post("report", body)
	if err != nil {
		r.log("report failed: %v", err)
		return
	}
	r.log("full report sent; %d task(s) returned", len(resp.Tasks))
	if len(resp.Tasks) > 0 {
		r.RunTasks(resp.Tasks)
	}
}

func (r *Runtime) postTaskReport() {
	hostname, _ := os.Hostname()
	pkgs, _ := winget.ListUpgrades()
	body := map[string]any{
		"action":       "post_task_report",
		"hostname":     hostname,
		"domain":       detectDomain(),
		"username":     os.Getenv("USERNAME"),
		"timestamp":    time.Now().Format("2006-01-02 15:04:05"),
		"packages":     pkgs,
		"update_count": len(pkgs),
		"agent_log":    r.drainLog(),
	}
	if _, err := r.post("report", body); err != nil {
		r.log("post-task report failed: %v", err)
	}
}

// wingetRetry calls fn once, and — if winget came back with
// APPINSTALLER_CLI_ERROR_PACKAGE_AGREEMENTS_NOT_ACCEPTED (0x8A150111) —
// refreshes source state and retries once. This catches the case where a
// stale source-agreement record made winget refuse even though our flag
// set already includes --accept-*-agreements.
func (r *Runtime) wingetRetry(fn func() (string, int)) (string, int) {
	out, code := fn()
	const agreementsErr = -1978334959 // 0x8A150111
	if code == agreementsErr {
		r.log("  → package agreements refused; refreshing sources and retrying once")
		if _, sc := winget.SourceUpdate(); sc != 0 {
			r.log("    source update returned %s", winget.ExitCodeResult(sc))
		}
		out, code = fn()
	}
	return out, code
}

// RunTasks executes tasks and posts results. After the batch finishes, if any
// task mutated the installed-package set (upgrade/install/uninstall), the
// agent re-runs `winget upgrade` and pushes a post_task_report so the server
// — and every WebSocket client — sees the fresh pending-update list.
func (r *Runtime) RunTasks(tasks []TaskRequest) {
	mutated := false
	for _, t := range tasks {
		r.log("task #%d: %s %s", t.ID, t.Type, t.PackageID)
		var out string
		var code int
		switch t.Type {
		case "upgrade_all":
			out, code = r.wingetRetry(winget.RunUpgradeAll)
			mutated = true
		case "upgrade_package":
			out, code = r.wingetRetry(func() (string, int) { return winget.RunUpgradeID(t.PackageID) })
			mutated = true
		case "install_package":
			out, code = r.wingetRetry(func() (string, int) { return winget.RunInstall(t.PackageID, t.PackageVersion) })
			mutated = true
		case "uninstall_package":
			out, code = r.wingetRetry(func() (string, int) { return winget.RunUninstall(t.PackageID) })
			mutated = true
		case "windows_update_all":
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
			out, code = winupdate.InstallAll(ctx, r.log)
			cancel()
			mutated = true
		case "windows_update_single":
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
			out, code = winupdate.InstallByID(ctx, t.PackageID, r.log)
			cancel()
			mutated = true
		case "check":
			out, code = "ok", 0
		case "uninstall_self":
			// Report success first, then kick off async cleanup and exit.
			r.post("task_result", map[string]any{
				"task_id": t.ID, "hostname": mustHost(), "result": "uninstalling",
			})
			r.log("uninstall_self: starting cleanup and exiting")
			r.spawnUninstaller()
			os.Exit(0)
		default:
			out, code = "unknown task type", -1
		}
		result := winget.ExitCodeResult(code)
		if code == -1 && !strings.HasPrefix(out, "exit") {
			result = "error: " + firstLine(out)
		}
		r.log("  task #%d => %s", t.ID, result)
		// Prefer WS; fall back to HTTP if the session went down while running.
		if !r.sendWS(map[string]any{
			"type": "task_result", "task_id": t.ID, "hostname": mustHost(), "result": result,
		}) {
			r.post("task_result", map[string]any{
				"task_id": t.ID, "hostname": mustHost(), "result": result,
			})
		}
	}
	if mutated {
		r.log("re-scanning installed packages after %d task(s)", len(tasks))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		r.fullScanWS(ctx)
	}
}

// -- system probes ----------------------------------------------------------

// psUTF8Prefix forces PowerShell to emit UTF-8 so non-ASCII output (localized
// OS captions, usernames, Windows Update titles) round-trips correctly to Go.
// Without this, Slovak/Czech/German/Polish installs produce replacement
// characters because PS defaults to the console code page.
const psUTF8Prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8; "

func detectDomain() string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		psUTF8Prefix+"$cs = Get-CimInstance Win32_ComputerSystem; if ($cs.PartOfDomain) { $cs.Domain } else { 'WORKGROUP' }")
	out, err := cmd.Output()
	if err != nil {
		return "WORKGROUP"
	}
	return strings.TrimSpace(string(out))
}

func detectOSVersion() string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		psUTF8Prefix+"$os = Get-CimInstance Win32_OperatingSystem; \"$($os.Caption) $($os.Version)\".Trim()")
	out, err := cmd.Output()
	if err != nil {
		return runtime.GOOS
	}
	return strings.TrimSpace(string(out))
}

type localUser struct {
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	LastLogon   string `json:"last_logon"`
}

func detectLocalUsers() []localUser {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		psUTF8Prefix+`Get-LocalUser | Select-Object Name,FullName,Enabled,Description,@{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}} | ConvertTo-Json -Compress`)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	b := bytes.TrimSpace(out)
	if len(b) == 0 {
		return nil
	}
	if b[0] == '{' {
		b = append([]byte{'['}, append(b, ']')...)
	}
	var raw []struct {
		Name        string `json:"Name"`
		FullName    string `json:"FullName"`
		Enabled     bool   `json:"Enabled"`
		Description string `json:"Description"`
		LastLogon   string `json:"LastLogon"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	out2 := make([]localUser, 0, len(raw))
	for _, u := range raw {
		out2 = append(out2, localUser{
			Name: u.Name, FullName: u.FullName, Enabled: u.Enabled,
			Description: u.Description, LastLogon: u.LastLogon,
		})
	}
	return out2
}

type localAdmin struct {
	Name            string `json:"name"`
	ObjectClass     string `json:"object_class"`
	PrincipalSource string `json:"principal_source"`
}

func detectLocalAdmins() []localAdmin {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		psUTF8Prefix+`Get-LocalGroupMember -Group 'Administrators' | Select-Object @{n='Name';e={$_.Name}},@{n='ObjectClass';e={"$($_.ObjectClass)"}},@{n='PrincipalSource';e={"$($_.PrincipalSource)"}} | ConvertTo-Json -Compress`)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	b := bytes.TrimSpace(out)
	if len(b) == 0 {
		return nil
	}
	if b[0] == '{' {
		b = append([]byte{'['}, append(b, ']')...)
	}
	var raw []struct {
		Name            string `json:"Name"`
		ObjectClass     string `json:"ObjectClass"`
		PrincipalSource string `json:"PrincipalSource"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	out2 := make([]localAdmin, 0, len(raw))
	for _, u := range raw {
		out2 = append(out2, localAdmin{
			Name: u.Name, ObjectClass: u.ObjectClass, PrincipalSource: u.PrincipalSource,
		})
	}
	return out2
}

// ensureWinget makes sure winget.exe is available. If not, it runs the
// embedded PowerShell installer and streams each output line back through the
// normal agent log (which in turn streams live to the dashboard).
func (r *Runtime) ensureWinget() {
	_, err := winget.EnsureInstalled(r.log)
	if err != nil {
		r.log("ensureWinget: %v", err)
	}
}

// -- self-update -----------------------------------------------------------

// checkSelfUpdate queries the server for the current binary SHA256 and, if it
// differs from our own, downloads the new binary, rotates files, and exits.
// The Windows service's recovery actions will restart us on the new binary.
func (r *Runtime) checkSelfUpdate() {
	if r.selfSha == "" {
		return
	}
	u := strings.TrimRight(r.Cfg.Server, "/") + "/api/?action=agent_version"
	req, _ := http.NewRequest("GET", u, nil)
	if r.Cfg.AgentToken != "" {
		req.Header.Set("X-Corrivex-Token", r.Cfg.AgentToken)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var vr struct {
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil || vr.SHA256 == "" {
		return
	}
	if strings.EqualFold(vr.SHA256, r.selfSha) {
		return
	}
	r.log("self-update: server has %s, we have %s (%d bytes available)",
		shortHash(vr.SHA256), shortHash(r.selfSha), vr.Size)

	// Download the new binary alongside the running exe.
	domain := detectDomain()
	dl := strings.TrimRight(r.Cfg.Server, "/") + "/api/?action=agent.exe&domain=" + url.QueryEscape(domain)
	self, _ := os.Executable()
	dir := filepath.Dir(self)
	newPath := filepath.Join(dir, "corrivex-agent.new.exe")
	if err := r.downloadFile(dl, newPath); err != nil {
		r.log("self-update: download failed: %v", err)
		return
	}
	sum, err := fileSHA256(newPath)
	if err != nil {
		r.log("self-update: hash failed: %v", err)
		os.Remove(newPath)
		return
	}
	if !strings.EqualFold(sum, vr.SHA256) {
		r.log("self-update: hash mismatch after download (%s vs %s)",
			shortHash(sum), shortHash(vr.SHA256))
		os.Remove(newPath)
		return
	}
	// Rotate: running exe → .old, new → running name.
	oldPath := self + ".old"
	os.Remove(oldPath)
	if err := os.Rename(self, oldPath); err != nil {
		r.log("self-update: rename current failed: %v", err)
		os.Remove(newPath)
		return
	}
	if err := os.Rename(newPath, self); err != nil {
		r.log("self-update: rename new failed: %v — reverting", err)
		os.Rename(oldPath, self)
		return
	}
	r.log("self-update: rotated binary, exiting for SCM restart")
	// Exit non-zero so the Windows SCM recovery actions restart us.
	os.Exit(1)
}

func (r *Runtime) downloadFile(u, dst string) error {
	req, _ := http.NewRequest("GET", u, nil)
	if r.Cfg.AgentToken != "" {
		req.Header.Set("X-Corrivex-Token", r.Cfg.AgentToken)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download http %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func selfSHA256() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	sum, err := fileSHA256(self)
	if err != nil {
		return ""
	}
	return sum
}

func shortHash(h string) string {
	if len(h) < 10 {
		return h
	}
	return h[:10]
}

// cleanupStaleBinary removes the `.old` copy of ourselves left behind by the
// last self-update on startup.
func cleanupStaleBinary() {
	self, err := os.Executable()
	if err != nil {
		return
	}
	os.Remove(self + ".old")
}

// -- uninstall_self --------------------------------------------------------

// spawnUninstaller writes a detached batch script that waits a few seconds,
// stops and removes the service, then deletes C:\ProgramData\Corrivex. It is
// intentionally fire-and-forget; once spawned, the agent process exits so the
// script can finish without a running exe in the way.
func (r *Runtime) spawnUninstaller() {
	svc := sanitizeServiceName(r.Cfg.ServiceName)
	if svc == "" {
		svc = "CorrivexAgent"
	}
	script := fmt.Sprintf(`@echo off
timeout /t 5 /nobreak > nul
sc stop "%s" > nul 2>&1
timeout /t 3 /nobreak > nul
sc delete "%s" > nul 2>&1
rmdir /s /q "C:\ProgramData\Corrivex" > nul 2>&1
del "%%~f0"
`, svc, svc)
	path := filepath.Join(os.TempDir(), "corrivex-uninstall.bat")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		r.log("uninstall_self: write script failed: %v", err)
		return
	}
	cmd := exec.Command("cmd.exe", "/c", "start", "/b", "", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008} // DETACHED_PROCESS
	if err := cmd.Start(); err != nil {
		r.log("uninstall_self: spawn failed: %v", err)
	}
}

func sanitizeServiceName(display string) string {
	r := strings.NewReplacer(" ", "", "\t", "", "/", "", "\\", "")
	return r.Replace(display)
}

func mustHost() string { h, _ := os.Hostname(); return h }
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
