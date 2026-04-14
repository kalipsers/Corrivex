// Package api implements the Corrivex HTTP API (port of api.php).
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/markov/corrivex/internal/auth"
	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/events"
	"github.com/markov/corrivex/internal/hub"
	"github.com/markov/corrivex/internal/version"
)

type Server struct {
	DB           *db.DB
	AgentBinary  []byte // embedded corrivex-agent.exe
	AgentSHA256  string // hex sha256 of AgentBinary
	APISecret    string // empty disables auth
	Broker       *events.Broker
	Hub          *hub.Hub
	mux          *http.ServeMux
	hostRe       *regexp.Regexp
}

func New(d *db.DB, agentBin []byte, secret string, br *events.Broker, hb *hub.Hub) *Server {
	s := &Server{
		DB:          d,
		AgentBinary: agentBin,
		APISecret:   secret,
		Broker:      br,
		Hub:         hb,
		mux:         http.NewServeMux(),
		hostRe:      regexp.MustCompile(`[^a-zA-Z0-9_\-\.]`),
	}
	if len(agentBin) > 0 {
		sum := sha256.Sum256(agentBin)
		s.AgentSHA256 = hex.EncodeToString(sum[:])
	}
	s.mux.HandleFunc("/api/", s.route)
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	action := r.URL.Query().Get("action")
	method := r.Method

	// ---- agent endpoints (token auth) + public helpers -----------------
	switch {
	case action == "server_version":
		writeJSON(w, 200, map[string]string{"version": version.Version})
		return
	case action == "agent_ws":
		s.agentWS(w, r)
		return
	case method == "GET" && action == "bootstrap":
		s.bootstrap(w, r)
		return
	case method == "GET" && action == "agent.exe":
		s.agentBinary(w, r)
		return
	case method == "GET" && action == "agent_version":
		s.agentVersion(w, r)
		return
	case method == "POST" && action == "ping":
		s.ping(w, r)
		return
	case method == "POST" && action == "report":
		s.report(w, r)
		return
	case method == "POST" && action == "task_result":
		s.taskResult(w, r)
		return
	// ---- auth endpoints (no session required) --------------------------
	case method == "GET" && action == "auth_state":
		s.authState(w, r)
		return
	case method == "POST" && action == "setup_first_admin":
		s.setupFirstAdmin(w, r)
		return
	case method == "POST" && action == "login":
		s.login(w, r)
		return
	case method == "POST" && action == "logout":
		s.logout(w, r)
		return
	}

	// ---- dashboard/API (require authenticated session) -----------------
	user, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	switch {
	case action == "ws":
		s.ws(w, r)
	case method == "GET" && action == "me":
		writeJSON(w, 200, publicUser(user))
	case method == "GET" && action == "users":
		s.requireRoleReq(w, r, user, auth.RoleAdmin, s.listUsers)
	case method == "POST" && action == "create_user":
		s.requireRoleReq(w, r, user, auth.RoleAdmin, s.createUser)
	case method == "POST" && action == "update_user":
		s.requireRoleReq(w, r, user, auth.RoleAdmin, s.updateUser)
	case method == "POST" && action == "delete_user":
		s.requireRoleReq(w, r, user, auth.RoleAdmin, s.deleteUser)
	case method == "POST" && action == "totp_begin":
		s.totpBegin(w, r, user)
	case method == "POST" && action == "totp_enable":
		s.totpEnable(w, r, user)
	case method == "POST" && action == "totp_disable":
		s.totpDisable(w, r, user)
	case method == "POST" && action == "change_password":
		s.changePassword(w, r, user)
	case method == "POST" && action == "remove_device":
		s.requireRoleReq(w, r, user, auth.RoleOperator, s.removeDevice)
	case method == "POST" && action == "create_task":
		s.requireRoleReq(w, r, user, auth.RoleOperator, s.createTask)
	case method == "POST" && action == "add_domain":
		s.requireRoleReq(w, r, user, auth.RoleAdmin, s.addDomain)
	case method == "POST" && action == "remove_domain":
		s.requireRoleReq(w, r, user, auth.RoleAdmin, s.removeDomain)
	case method == "POST" && action == "set_settings":
		s.requireRoleReq(w, r, user, auth.RoleAdmin, s.setSettings)
	case method == "GET" && action == "debug":
		s.debug(w, r)
	case method == "GET" && action == "get_settings":
		s.getSettings(w, r)
	case method == "GET" && action == "search_packages":
		s.searchPackages(w, r)
	case method == "GET" && action == "domains":
		s.listDomains(w, r)
	case method == "GET" && action == "tasks":
		s.hostTasks(w, r)
	case method == "GET" && r.URL.Query().Get("host") != "":
		s.singlePC(w, r)
	case method == "GET":
		s.allPCs(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not found"})
	}
}

// -- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if comma := strings.Index(xf, ","); comma > 0 {
			return strings.TrimSpace(xf[:comma])
		}
		return strings.TrimSpace(xf)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) normalizeHost(h string) string {
	return strings.ToUpper(s.hostRe.ReplaceAllString(strings.TrimSpace(h), "_"))
}

func (s *Server) checkSecret(r *http.Request, body map[string]any) bool {
	if s.APISecret == "" {
		return true
	}
	if r.Header.Get("X-API-Secret") == s.APISecret {
		return true
	}
	if body != nil {
		if v, ok := body["secret"].(string); ok && v == s.APISecret {
			return true
		}
	}
	return false
}

// authAgent implements TOFU per-agent authentication. It returns the token
// the agent should use going forward. On the first call (no token stored for
// this hostname) the server adopts any token the client sent, or mints a new
// one. Once a token exists, clients must present it exactly.
//
// ok=false means a 4xx/5xx response has already been written.
func (s *Server) authAgent(w http.ResponseWriter, r *http.Request, hostname string) (token string, ok bool) {
	stored, err := s.DB.GetAgentToken(hostname)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return "", false
	}
	sent := r.Header.Get("X-Corrivex-Token")
	if stored == "" {
		issued := strings.TrimSpace(sent)
		if issued == "" {
			issued = randomToken()
		}
		if err := s.DB.SetAgentToken(hostname, issued); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return "", false
		}
		return issued, true
	}
	if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(stored)) != 1 {
		writeJSON(w, 401, map[string]string{"error": "invalid agent token"})
		return "", false
	}
	return stored, true
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// -- handlers ---------------------------------------------------------------

func (s *Server) debug(w http.ResponseWriter, r *http.Request) {
	versions, _ := s.DB.SchemaVersions()
	domains, _ := s.DB.AllowedDomains()
	writeJSON(w, 200, map[string]any{
		"schema_versions": versions,
		"allowed_domains": domains,
	})
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.DB.AllSettings()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, settings)
}

func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	allowed := map[string]bool{
		"check_interval_minutes":   true,
		"full_scan_interval_hours": true,
		"install_service":          true,
		"service_name":             true,
	}
	for k, v := range body {
		if !allowed[k] {
			continue
		}
		s.DB.SetSetting(k, fmt.Sprint(v))
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) searchPackages(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		writeJSON(w, 400, map[string]string{"error": "Query too short"})
		return
	}
	if cached, ok := s.DB.PackageCacheGet(q); ok {
		writeJSON(w, 200, map[string]any{"source": "cache", "results": cached})
		return
	}
	u := "https://api.winget.run/v2/packages?" + url.Values{"search": {q}, "limit": {"30"}}.Encode()
	results := fetchWinget(u)
	if results == nil {
		u2 := "https://winget.run/api/v2/packages?" + url.Values{"search": {q}}.Encode()
		results = fetchWinget(u2)
	}
	if results == nil {
		writeJSON(w, 503, map[string]string{"error": "Package search unavailable"})
		return
	}
	b, _ := json.Marshal(results)
	s.DB.PackageCacheSet(q, b)
	writeJSON(w, 200, map[string]any{"source": "api", "results": results})
}

type pkgResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	Version   string `json:"version"`
}

func fetchWinget(u string) []pkgResult {
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Corrivex/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	var list []any
	if d, ok := raw["Data"].([]any); ok {
		list = d
	} else if d, ok := raw["packages"].([]any); ok {
		list = d
	}
	var out []pkgResult
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pr := pkgResult{
			ID:        firstStr(m, "Id", "PackageIdentifier"),
			Name:      firstStr(m, "Name", "PackageName"),
			Publisher: firstStr(m, "Publisher"),
		}
		if versions, ok := m["Versions"].([]any); ok && len(versions) > 0 {
			if vs, ok := versions[0].(string); ok {
				pr.Version = vs
			}
		} else {
			pr.Version = firstStr(m, "Version")
		}
		out = append(out, pr)
	}
	if out == nil {
		return []pkgResult{}
	}
	return out
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// -- Bootstrap & agent download --------------------------------------------

func serverBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	host := s.normalizeHost(r.URL.Query().Get("host"))
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	allowed, err := s.DB.IsDomainAllowed(domain)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !allowed {
		fmt.Fprintf(w, "# Corrivex: domain %q is not in the allowed list. Contact your administrator.\n", domain)
		return
	}
	base := serverBaseURL(r)
	checkMin, _ := strconv.Atoi(s.DB.Setting("check_interval_minutes", "1"))
	scanHours, _ := strconv.Atoi(s.DB.Setting("full_scan_interval_hours", "24"))
	serviceName := s.DB.Setting("service_name", "Corrivex Agent")

	fmt.Fprintf(w, installScript, base, host, domain, checkMin, scanHours, serviceName)
}

func (s *Server) agentBinary(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if ok, _ := s.DB.IsDomainAllowed(domain); !ok {
		http.Error(w, "domain not allowed", http.StatusForbidden)
		return
	}
	if len(s.AgentBinary) == 0 {
		http.Error(w, "agent not embedded", 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="corrivex-agent.exe"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(s.AgentBinary)))
	w.Write(s.AgentBinary)
}

// PowerShell installer: downloads agent.exe, runs it with 'install'.
// Re-runs are safe: the existing service is stopped before overwriting the
// exe, and corrivex-agent.exe install preserves any existing AgentToken so
// the host keeps its TOFU identity with the server.
const installScript = `# Corrivex bootstrap | generated by server
$ErrorActionPreference = 'Stop'
$Server   = '%s'
$Host0    = '%s'
$Domain   = '%s'
$CheckMin = %d
$ScanHrs  = %d
$SvcName  = '%s'
$Dir      = 'C:\ProgramData\Corrivex'
if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
$Exe = Join-Path $Dir 'corrivex-agent.exe'

# If an agent is already installed, stop its service so we can overwrite the exe.
$SvcInternal = ($SvcName -replace '[\s/\\]','')
$existing = Get-Service -Name $SvcInternal -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Corrivex: stopping existing service '$SvcInternal' ..."
    try { Stop-Service -Name $SvcInternal -Force -ErrorAction Stop } catch {}
    $deadline = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $deadline) {
        try {
            $h = [System.IO.File]::Open($Exe, 'Open', 'ReadWrite', 'None')
            $h.Close(); break
        } catch { Start-Sleep -Milliseconds 500 }
    }
}

$Url = "$Server/api/?action=agent.exe&domain=$Domain"
Write-Host "Corrivex: downloading agent from $Url"
Invoke-WebRequest -Uri $Url -OutFile $Exe -UseBasicParsing
Write-Host "Corrivex: installing service '$SvcName'"
& $Exe install --server="$Server" --check-min=$CheckMin --scan-hrs=$ScanHrs --svc-name="$SvcName"
Write-Host "Corrivex: done."
`

// -- Ping / report / task_result ------------------------------------------

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	decode(r, &body)
	if !s.checkSecret(r, body) {
		writeJSON(w, 403, map[string]string{"error": "Forbidden"})
		return
	}
	hostname := ""
	if v, ok := body["hostname"].(string); ok {
		hostname = s.normalizeHost(v)
	}
	if hostname == "" {
		writeJSON(w, 400, map[string]string{"error": "Missing hostname"})
		return
	}
	token, ok := s.authAgent(w, r, hostname)
	if !ok {
		return
	}
	if err := s.DB.TouchLastSeen(hostname); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	tasks, err := s.DB.PendingTasks(hostname)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.publishPC(hostname)
	s.publishDeliveredTasks(hostname, tasks)
	writeJSON(w, 200, map[string]any{
		"status":       "ok",
		"tasks":        tasks,
		"agent_token":  token,
		"agent_sha256": s.AgentSHA256,
	})
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if len(body) == 0 {
		writeJSON(w, 400, map[string]string{"error": "Missing body"})
		return
	}
	var generic map[string]any
	json.Unmarshal(body, &generic)
	if !s.checkSecret(r, generic) {
		writeJSON(w, 403, map[string]string{"error": "Forbidden"})
		return
	}
	var rep db.FullReport
	if err := json.Unmarshal(body, &rep); err != nil {
		writeJSON(w, 400, map[string]string{"error": "Bad json"})
		return
	}
	host := rep.Hostname
	if host == "" {
		host = rep.Host
	}
	hostname := s.normalizeHost(host)
	if hostname == "" {
		writeJSON(w, 400, map[string]string{"error": "Missing hostname"})
		return
	}
	token, ok := s.authAgent(w, r, hostname)
	if !ok {
		return
	}
	tasks, err := s.DB.StoreFullReport(rep, clientIP(r))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.publishPC(hostname)
	s.publishDeliveredTasks(hostname, tasks)
	writeJSON(w, 200, map[string]any{
		"status":       "ok",
		"tasks":        tasks,
		"agent_token":  token,
		"agent_sha256": s.AgentSHA256,
	})
}

func (s *Server) taskResult(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TaskID   int64  `json:"task_id"`
		Hostname string `json:"hostname"`
		Result   string `json:"result"`
	}
	decode(r, &body)
	hostname := s.normalizeHost(body.Hostname)
	if hostname != "" {
		if _, ok := s.authAgent(w, r, hostname); !ok {
			return
		}
	}
	if body.TaskID > 0 {
		s.DB.CompleteTask(body.TaskID, body.Result)
		t, _ := s.DB.GetTask(body.TaskID)
		// Special case: uninstall_self → hard-delete the PC from the DB
		// once the agent confirms it has started removing itself.
		if t != nil && t.Type == "uninstall_self" {
			host := t.Hostname
			_ = s.DB.DeletePC(host)
			s.Broker.Publish("pc_removed", map[string]string{"hostname": host})
		} else {
			evt := map[string]any{
				"task_id":  body.TaskID,
				"hostname": hostname,
				"result":   body.Result,
				"status":   classifyResult(body.Result),
			}
			if t != nil {
				evt["type"] = t.Type
				if t.PackageID != nil {
					evt["package_id"] = *t.PackageID
				}
				if t.PackageName != nil {
					evt["package_name"] = *t.PackageName
				}
			}
			s.Broker.Publish("task", evt)
		}
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// agentVersion reports the SHA256 + size of the embedded corrivex-agent.exe
// so agents can compare it to their own binary and self-update.
// No auth required: the hash is public information.
func (s *Server) agentVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"sha256": s.AgentSHA256,
		"size":   len(s.AgentBinary),
	})
}

// =============================================================================
// Persistent agent WebSocket
// =============================================================================

// agentWS is the long-lived connection an agent opens on startup. The agent
// authenticates with its hostname + TOFU token in a `hello` frame, then the
// two sides exchange JSON messages:
//
//	← {type:"hello",hostname,token,domain,agent_sha256}
//	  → {type:"hello_ok",agent_token,agent_sha256}  (issues a fresh token if needed)
//	← {type:"report", …}                             → stores full_report
//	← {type:"task_result", task_id, result}          → marks task complete
//	← {type:"log", line}                             → fanned out to dashboard
//	← {type:"pong"}                                  → heartbeat reply
//	  → {type:"task", task:{…}}                       (dashboard pushed a task)
//	  → {type:"ping"}                                 (keepalive)
func (s *Server) agentWS(w http.ResponseWriter, r *http.Request) {
	if s.Hub == nil {
		http.Error(w, "no hub", 500)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	// Keep connection open indefinitely; the read loop guards liveness.
	c.SetReadLimit(8 << 20) // 8 MiB frames (a full report can be large)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer c.CloseNow()

	// First frame must be a hello.
	readCtx, readCancel := context.WithTimeout(ctx, 20*time.Second)
	_, helloBytes, err := c.Read(readCtx)
	readCancel()
	if err != nil {
		return
	}
	var hello struct {
		Type         string `json:"type"`
		Hostname     string `json:"hostname"`
		Token        string `json:"token"`
		Domain       string `json:"domain"`
		AgentSHA256  string `json:"agent_sha256"`
		AgentVersion string `json:"agent_version"`
	}
	if err := json.Unmarshal(helloBytes, &hello); err != nil || hello.Type != "hello" {
		c.Close(websocket.StatusPolicyViolation, "bad hello")
		return
	}
	hostname := s.normalizeHost(hello.Hostname)
	if hostname == "" {
		c.Close(websocket.StatusPolicyViolation, "missing hostname")
		return
	}
	if hello.AgentVersion != "" {
		log.Printf("agent_ws: %s connected (agent v%s)", hostname, hello.AgentVersion)
	}

	// TOFU authenticate using the same helper as the HTTP endpoints, but
	// feeding the token via a synthesized request header.
	// We reuse authAgent's semantics by injecting the token here.
	stored, dbErr := s.DB.GetAgentToken(hostname)
	if dbErr != nil {
		c.Close(websocket.StatusInternalError, "db error")
		return
	}
	issuedToken := stored
	if stored == "" {
		issued := strings.TrimSpace(hello.Token)
		if issued == "" {
			issued = randomToken()
		}
		if err := s.DB.SetAgentToken(hostname, issued); err != nil {
			c.Close(websocket.StatusInternalError, "token store error")
			return
		}
		issuedToken = issued
	} else {
		if hello.Token == "" || subtle.ConstantTimeCompare([]byte(hello.Token), []byte(stored)) != 1 {
			c.Close(websocket.StatusPolicyViolation, "invalid token")
			return
		}
	}

	// Register connection in the hub. The Close hook here cancels the outer
	// context so both reader and writer unwind cleanly.
	sendCh := make(chan []byte, 64)
	connCtx, connCancel := context.WithCancel(ctx)
	closeOnce := sync.OnceFunc(func() {
		connCancel()
		c.Close(websocket.StatusNormalClosure, "evicted")
	})
	hc := &hub.Conn{Hostname: hostname, Send: sendCh, Close: closeOnce}
	s.Hub.Register(hc)
	defer func() {
		s.Hub.Unregister(hc)
		s.Broker.Publish("pc_online", map[string]any{"hostname": hostname, "online": false})
	}()

	// Respond with hello_ok + any tasks that were queued before this connection.
	helloOK, _ := json.Marshal(map[string]any{
		"type":         "hello_ok",
		"agent_token":  issuedToken,
		"agent_sha256": s.AgentSHA256,
	})
	if err := c.Write(ctx, websocket.MessageText, helloOK); err != nil {
		return
	}

	// Touch last_seen and announce online.
	_ = s.DB.TouchLastSeen(hostname)
	s.Broker.Publish("pc_online", map[string]any{"hostname": hostname, "online": true})
	s.publishPC(hostname)

	// Deliver any pending tasks immediately.
	if tasks, err := s.DB.PendingTasks(hostname); err == nil && len(tasks) > 0 {
		for _, t := range tasks {
			payload := map[string]any{
				"type": "task",
				"task": map[string]any{
					"id":              t.ID,
					"type":            t.Type,
					"package_id":      strPtr(t.PackageID),
					"package_name":    strPtr(t.PackageName),
					"package_version": strPtr(t.PackageVersion),
				},
			}
			if b, err := json.Marshal(payload); err == nil {
				select {
				case sendCh <- b:
				default:
				}
			}
		}
		s.publishDeliveredTasks(hostname, tasks)
	}

	// Writer goroutine: drain sendCh and also send periodic app-level pings
	// (on top of the transport-level pings coder/websocket does automatically).
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case msg, ok := <-sendCh:
				if !ok {
					return
				}
				wc, cancel := context.WithTimeout(connCtx, 10*time.Second)
				err := c.Write(wc, websocket.MessageText, msg)
				cancel()
				if err != nil {
					closeOnce()
					return
				}
			case <-t.C:
				wc, cancel := context.WithTimeout(connCtx, 10*time.Second)
				err := c.Write(wc, websocket.MessageText, []byte(`{"type":"ping"}`))
				cancel()
				if err != nil {
					closeOnce()
					return
				}
			}
		}
	}()

	// Reader loop.
	for {
		_, data, err := c.Read(connCtx)
		if err != nil {
			return
		}
		s.handleAgentFrame(hostname, data, r)
	}
}

func (s *Server) handleAgentFrame(hostname string, data []byte, r *http.Request) {
	var env struct{ Type string `json:"type"` }
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}
	switch env.Type {
	case "pong":
		// heartbeat
	case "report":
		var rep db.FullReport
		if err := json.Unmarshal(data, &rep); err != nil {
			return
		}
		if rep.Hostname == "" && rep.Host == "" {
			rep.Hostname = hostname
		}
		if _, err := s.DB.StoreFullReport(rep, clientIP(r)); err == nil {
			s.publishPC(hostname)
		}
	case "task_result":
		var body struct {
			TaskID int64  `json:"task_id"`
			Result string `json:"result"`
		}
		if err := json.Unmarshal(data, &body); err != nil || body.TaskID == 0 {
			return
		}
		s.DB.CompleteTask(body.TaskID, body.Result)
		t, _ := s.DB.GetTask(body.TaskID)
		if t != nil && t.Type == "uninstall_self" {
			_ = s.DB.DeletePC(hostname)
			s.Broker.Publish("pc_removed", map[string]string{"hostname": hostname})
			return
		}
		evt := map[string]any{
			"task_id":  body.TaskID,
			"hostname": hostname,
			"result":   body.Result,
			"status":   classifyResult(body.Result),
		}
		if t != nil {
			evt["type"] = t.Type
			if t.PackageID != nil {
				evt["package_id"] = *t.PackageID
			}
			if t.PackageName != nil {
				evt["package_name"] = *t.PackageName
			}
		}
		s.Broker.Publish("task", evt)
	case "log":
		var body struct {
			Line  string `json:"line"`
			Level string `json:"level,omitempty"`
		}
		if err := json.Unmarshal(data, &body); err != nil || body.Line == "" {
			return
		}
		s.Broker.Publish("log", map[string]any{
			"hostname": hostname,
			"ts":       time.Now().Format("15:04:05"),
			"level":    body.Level,
			"line":     body.Line,
		})
	}
}

func strPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// classifyResult maps an agent-reported result string to a status label the
// UI understands. Anything that is an explicit error or exit:N from winget
// counts as failed; everything else (including "already_up_to_date" and the
// reboot-required variants) is treated as completed.
func classifyResult(result string) string {
	r := strings.ToLower(strings.TrimSpace(result))
	if r == "" {
		return "completed"
	}
	if strings.HasPrefix(r, "error:") || strings.HasPrefix(r, "exit:") ||
		strings.Contains(r, "not_found") || strings.Contains(r, "no_applicable") {
		return "failed"
	}
	return "completed"
}

// publishDeliveredTasks emits a "task" event with status=delivered for every
// task we just handed off to an agent, so any open dashboard shows the row
// transition from "queued" → "running" in real time.
func (s *Server) publishDeliveredTasks(hostname string, tasks []db.Task) {
	for _, t := range tasks {
		evt := map[string]any{
			"task_id":  t.ID,
			"hostname": hostname,
			"type":     t.Type,
			"status":   "delivered",
		}
		if t.PackageID != nil {
			evt["package_id"] = *t.PackageID
		}
		if t.PackageName != nil {
			evt["package_name"] = *t.PackageName
		}
		s.Broker.Publish("task", evt)
	}
}

// removeDevice queues an uninstall_self task for the given host. When the
// agent reports the task complete, taskResult() deletes the host entirely.
func (s *Server) removeDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hostname string `json:"hostname"`
		Force    bool   `json:"force"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "Bad json"})
		return
	}
	hostname := s.normalizeHost(body.Hostname)
	if hostname == "" {
		writeJSON(w, 400, map[string]string{"error": "Missing hostname"})
		return
	}
	if body.Force {
		if err := s.DB.DeletePC(hostname); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		s.Broker.Publish("pc_removed", map[string]string{"hostname": hostname})
		writeJSON(w, 200, map[string]string{"status": "removed"})
		return
	}
	id, err := s.DB.CreateTask(hostname, "uninstall_self", nil, nil, nil)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.Broker.Publish("task", map[string]any{
		"task_id": id, "hostname": hostname, "type": "uninstall_self", "status": "pending",
	})
	writeJSON(w, 200, map[string]any{"status": "ok", "task_id": id})
}

// -- Dashboard-facing endpoints --------------------------------------------

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hostname       string `json:"hostname"`
		Type           string `json:"type"`
		PackageID      string `json:"package_id"`
		PackageName    string `json:"package_name"`
		PackageVersion string `json:"package_version"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "Bad json"})
		return
	}
	hostname := s.normalizeHost(body.Hostname)
	valid := map[string]bool{
		"upgrade_all": true, "upgrade_package": true, "install_package": true,
		"uninstall_package": true, "check": true,
		"windows_update_all": true, "windows_update_single": true,
	}
	if hostname == "" || !valid[body.Type] {
		writeJSON(w, 400, map[string]string{"error": "Invalid input"})
		return
	}
	var pid, pname, pver *string
	if body.PackageID != "" {
		pid = &body.PackageID
	}
	if body.PackageName != "" {
		pname = &body.PackageName
	}
	if body.PackageVersion != "" {
		pver = &body.PackageVersion
	}
	id, err := s.DB.CreateTask(hostname, body.Type, pid, pname, pver)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	status := "pending"
	// If the agent is connected right now, push the task immediately and
	// mark it delivered so the dashboard sees a "running" chip at once.
	if s.pushTaskIfOnline(hostname, id, body.Type, body.PackageID, body.PackageName, body.PackageVersion) {
		status = "delivered"
	}
	s.Broker.Publish("task", map[string]any{
		"task_id": id, "hostname": hostname, "type": body.Type,
		"package_id": body.PackageID, "package_name": body.PackageName,
		"status": status,
	})
	writeJSON(w, 200, map[string]any{"status": "ok", "task_id": id})
}

// pushTaskIfOnline sends the task payload to the connected agent right away.
// On success it also marks the task delivered server-side so subsequent
// refreshes see a coherent state.
func (s *Server) pushTaskIfOnline(hostname string, id int64, typ, pkgID, pkgName, pkgVer string) bool {
	if s.Hub == nil || !s.Hub.IsOnline(hostname) {
		return false
	}
	payload := map[string]any{
		"type": "task",
		"task": map[string]any{
			"id":               id,
			"type":             typ,
			"package_id":       pkgID,
			"package_name":     pkgName,
			"package_version":  pkgVer,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	if !s.Hub.Send(hostname, raw) {
		return false
	}
	_ = s.DB.MarkTaskDelivered(id)
	return true
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		Notes  string `json:"notes"`
	}
	decode(r, &body)
	body.Domain = strings.ToLower(strings.TrimSpace(body.Domain))
	if body.Domain == "" {
		writeJSON(w, 400, map[string]string{"error": "Missing domain"})
		return
	}
	s.DB.AddAllowedDomain(body.Domain, body.Notes)
	s.Broker.Publish("domain", map[string]any{"action": "added", "domain": body.Domain})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) removeDomain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int `json:"id"`
	}
	decode(r, &body)
	if body.ID == 0 {
		writeJSON(w, 400, map[string]string{"error": "Missing id"})
		return
	}
	s.DB.RemoveAllowedDomain(body.ID)
	s.Broker.Publish("domain", map[string]any{"action": "removed", "id": body.ID})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	doms, err := s.DB.AllowedDomains()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, doms)
}

func (s *Server) hostTasks(w http.ResponseWriter, r *http.Request) {
	host := s.normalizeHost(r.URL.Query().Get("host"))
	tasks, err := s.DB.TasksForHost(host, 30)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, tasks)
}

func (s *Server) singlePC(w http.ResponseWriter, r *http.Request) {
	pc, err := s.DB.GetPC(r.URL.Query().Get("host"))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if pc == nil {
		writeJSON(w, 404, map[string]string{"error": "Not found"})
		return
	}
	writeJSON(w, 200, s.pcWithOnline(pc))
}

func (s *Server) allPCs(w http.ResponseWriter, r *http.Request) {
	pcs, err := s.DB.AllPCs(r.URL.Query().Get("domain"))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	online := map[string]bool{}
	if s.Hub != nil {
		online = s.Hub.OnlineHosts()
	}
	out := make([]map[string]any, 0, len(pcs))
	for i := range pcs {
		out = append(out, pcMap(&pcs[i], online[pcs[i].Hostname]))
	}
	writeJSON(w, 200, out)
}

// publishPC fetches the current PC row and emits a "pc" event (includes
// online flag so the dashboard can refresh the indicator in place).
func (s *Server) publishPC(hostname string) {
	if hostname == "" || s.Broker == nil {
		return
	}
	pc, err := s.DB.GetPC(hostname)
	if err != nil || pc == nil {
		return
	}
	s.Broker.Publish("pc", s.pcWithOnline(pc))
}

func (s *Server) pcWithOnline(pc *db.PC) map[string]any {
	online := false
	if s.Hub != nil {
		online = s.Hub.IsOnline(pc.Hostname)
	}
	return pcMap(pc, online)
}

func pcMap(pc *db.PC, online bool) map[string]any {
	return map[string]any{
		"id":               pc.ID,
		"hostname":         pc.Hostname,
		"domain":           pc.Domain,
		"os_version":       pc.OSVersion,
		"last_seen":        pc.LastSeen,
		"update_count":     pc.UpdateCount,
		"last_check_at":    pc.LastCheckAt,
		"last_upgrade_at":  pc.LastUpgradeAt,
		"last_full_report": pc.LastFullReport,
		"last_packages":    pc.LastPackages,
		"windows_updates":  pc.WindowsUpdates,
		"users":            pc.Users,
		"local_admins":     pc.LocalAdmins,
		"check_at":         pc.CheckAt,
		"check_user":       pc.CheckUser,
		"check_ip":         pc.CheckIP,
		"upgrade_at":       pc.UpgradeAt,
		"upgrade_user":     pc.UpgradeUser,
		"tasks":            pc.Tasks,
		"online":           online,
	}
}

// -- WebSocket endpoint ----------------------------------------------------

func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	if s.Broker == nil {
		http.Error(w, "no broker", 500)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // dashboard is same-origin; allow all
	})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	sub, unsub := s.Broker.Subscribe()
	defer unsub()

	// Reader goroutine: drain incoming frames and detect client disconnect.
	go func() {
		for {
			if _, _, err := c.Read(ctx); err != nil {
				cancel()
				return
			}
		}
	}()

	// Initial hello frame so clients can confirm the socket is ready.
	hello, _ := json.Marshal(Event{Type: "hello"})
	_ = c.Write(ctx, websocket.MessageText, hello)

	pingTicker := time.NewTicker(25 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		case ev, ok := <-sub:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			err = c.Write(wctx, websocket.MessageText, b)
			wcancel()
			if err != nil {
				return
			}
		}
	}
}

// Event mirrors events.Event so the websocket handler can marshal one-off messages
// (hello frame) without importing the broker type into the wire contract.
type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// =============================================================================
// Session middleware + user management
// =============================================================================

func (s *Server) currentSession(r *http.Request) (*db.User, bool) {
	c, err := r.Cookie(auth.SessionCookieName)
	if err != nil || c.Value == "" {
		return nil, false
	}
	_, user, err := s.DB.LookupSession(c.Value)
	if err != nil || user == nil {
		return nil, false
	}
	return user, true
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (*db.User, bool) {
	user, ok := s.currentSession(r)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
		return nil, false
	}
	return user, true
}

// requireRoleReq gates a handler that takes (w, r).
func (s *Server) requireRoleReq(w http.ResponseWriter, r *http.Request, user *db.User, need string, fn func(http.ResponseWriter, *http.Request)) {
	if !auth.HasRole(user.Role, need) {
		writeJSON(w, 403, map[string]string{"error": "insufficient role"})
		return
	}
	fn(w, r)
}

func publicUser(u *db.User) map[string]any {
	return map[string]any{
		"id":            u.ID,
		"username":      u.Username,
		"role":          u.Role,
		"totp_enabled":  u.TOTPEnabled,
		"created_at":    u.CreatedAt,
		"last_login_at": u.LastLoginAt,
	}
}

// authState tells the UI whether a first-run setup is needed and whether the
// caller has a valid session.
func (s *Server) authState(w http.ResponseWriter, r *http.Request) {
	n, err := s.DB.CountUsers()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	out := map[string]any{"users_exist": n > 0}
	if user, ok := s.currentSession(r); ok {
		out["user"] = publicUser(user)
	}
	writeJSON(w, 200, out)
}

// setupFirstAdmin is callable only when the users table is empty; it creates
// a single admin account and logs that account in.
func (s *Server) setupFirstAdmin(w http.ResponseWriter, r *http.Request) {
	n, err := s.DB.CountUsers()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if n > 0 {
		writeJSON(w, 403, map[string]string{"error": "setup already completed"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" || len(body.Password) < 8 {
		writeJSON(w, 400, map[string]string{"error": "username required and password must be ≥ 8 chars"})
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	id, err := s.DB.CreateUser(body.Username, hash, auth.RoleAdmin)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.issueSessionCookie(w, r, int(id))
	writeJSON(w, 200, map[string]any{"status": "ok", "role": auth.RoleAdmin})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	user, err := s.DB.GetUserByName(strings.TrimSpace(body.Username))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if user == nil || !auth.CheckPassword(user.PasswordHash, body.Password) {
		writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	if user.TOTPEnabled && user.TOTPSecret != nil {
		if body.TOTPCode == "" {
			writeJSON(w, 200, map[string]any{"totp_required": true})
			return
		}
		if !auth.Verify(*user.TOTPSecret, body.TOTPCode) {
			writeJSON(w, 401, map[string]string{"error": "invalid TOTP code"})
			return
		}
	}
	s.DB.TouchUserLogin(user.ID)
	s.issueSessionCookie(w, r, user.ID)
	writeJSON(w, 200, map[string]any{"status": "ok", "user": publicUser(user)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil && c.Value != "" {
		s.DB.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.SessionCookieName, Value: "", Path: "/",
		Expires: time.Unix(0, 0), MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: auth.CookieSecure(r),
	})
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) issueSessionCookie(w http.ResponseWriter, r *http.Request, userID int) {
	id, err := auth.NewSessionID()
	if err != nil {
		return
	}
	exp := time.Now().Add(12 * time.Hour)
	if err := s.DB.CreateSession(id, userID, exp, clientIP(r), r.UserAgent()); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.SessionCookieName, Value: id, Path: "/",
		Expires: exp, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: auth.CookieSecure(r),
	})
}

// -- password change for current user --------------------------------------

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, user *db.User) {
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	if !auth.CheckPassword(user.PasswordHash, body.Current) {
		writeJSON(w, 401, map[string]string{"error": "current password is wrong"})
		return
	}
	if len(body.New) < 8 {
		writeJSON(w, 400, map[string]string{"error": "password must be ≥ 8 chars"})
		return
	}
	hash, err := auth.HashPassword(body.New)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := s.DB.UpdateUserPassword(user.ID, hash); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// -- TOTP setup ------------------------------------------------------------

func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request, user *db.User) {
	secret := auth.NewSecret()
	otpURL := auth.OTPAuthURL("Corrivex", user.Username, secret)
	// Store but do not enable: the TOTPEnabled view is computed from the
	// column non-null, so we only write it once the user verifies their
	// first code. For a pending secret we just return it.
	resp := map[string]any{
		"secret":      secret,
		"otpauth_url": otpURL,
		"issuer":      "Corrivex",
		"account":     user.Username,
	}
	if dataURL, err := auth.QRDataURL(otpURL, 8, 2); err == nil {
		resp["qr_png"] = dataURL
	}
	writeJSON(w, 200, resp)
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request, user *db.User) {
	var body struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	if !auth.Verify(body.Secret, body.Code) {
		writeJSON(w, 400, map[string]string{"error": "code did not match secret"})
		return
	}
	if err := s.DB.SetUserTOTPSecret(user.ID, &body.Secret); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "enabled"})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, user *db.User) {
	var body struct {
		Current string `json:"current_password"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	if !auth.CheckPassword(user.PasswordHash, body.Current) {
		writeJSON(w, 401, map[string]string{"error": "current password is wrong"})
		return
	}
	if err := s.DB.SetUserTOTPSecret(user.ID, nil); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "disabled"})
}

// -- User CRUD (admin) -----------------------------------------------------

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(users))
	for i := range users {
		out = append(out, publicUser(&users[i]))
	}
	writeJSON(w, 200, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decode(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" || len(body.Password) < 8 {
		writeJSON(w, 400, map[string]string{"error": "username required and password must be ≥ 8 chars"})
		return
	}
	if !validRole(body.Role) {
		writeJSON(w, 400, map[string]string{"error": "invalid role"})
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	id, err := s.DB.CreateUser(body.Username, hash, body.Role)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "id": id})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID       int    `json:"id"`
		Role     string `json:"role,omitempty"`
		Password string `json:"password,omitempty"`
	}
	if err := decode(r, &body); err != nil || body.ID == 0 {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	if body.Role != "" {
		if !validRole(body.Role) {
			writeJSON(w, 400, map[string]string{"error": "invalid role"})
			return
		}
		if err := s.DB.UpdateUserRole(body.ID, body.Role); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
	}
	if body.Password != "" {
		if len(body.Password) < 8 {
			writeJSON(w, 400, map[string]string{"error": "password must be ≥ 8 chars"})
			return
		}
		hash, err := auth.HashPassword(body.Password)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := s.DB.UpdateUserPassword(body.ID, hash); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int `json:"id"`
	}
	if err := decode(r, &body); err != nil || body.ID == 0 {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	// Disallow deleting the last remaining admin.
	users, err := s.DB.ListUsers()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	admins := 0
	var target *db.User
	for i := range users {
		if users[i].Role == auth.RoleAdmin {
			admins++
		}
		if users[i].ID == body.ID {
			target = &users[i]
		}
	}
	if target != nil && target.Role == auth.RoleAdmin && admins <= 1 {
		writeJSON(w, 400, map[string]string{"error": "cannot delete the last admin"})
		return
	}
	if err := s.DB.DeleteUser(body.ID); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func validRole(r string) bool {
	switch r {
	case auth.RoleAdmin, auth.RoleOperator, auth.RoleViewer:
		return true
	}
	return false
}
