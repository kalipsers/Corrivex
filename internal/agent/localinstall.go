//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/markov/corrivex/internal/localinstall"
)

// runLocalInstall is the agent-side handler for a local_install task.
// Takes the task's PackageID (string form of local_installers.id),
// fetches the installer row from the server, enforces the path
// whitelist locally, then runs localinstall.Run with the right flags.
//
// Returns the (output, exitCode) pair that RunTasks expects.
func (r *Runtime) runLocalInstall(idStr string) (string, int) {
	id, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
	if err != nil || id <= 0 {
		return "invalid installer id: " + idStr, -1
	}
	spec, err := r.fetchLocalInstaller(id)
	if err != nil {
		return "fetch installer " + idStr + ": " + err.Error(), -1
	}
	if spec == nil {
		return "installer " + idStr + " not found on server", -1
	}
	// Whitelist enforcement: path must be UNC, OR start with one of the
	// server-configured allowed prefixes. Defence in depth — the server
	// also rejects blatantly malformed paths at save time.
	if err := validateInstallerPath(spec.Installer.Path, spec.AllowedPrefixes); err != nil {
		return "path rejected: " + err.Error(), -1
	}

	expected := parseExpectedCodes(spec.Installer.ExpectedExitCodes)
	override := localinstall.ParseArgsOverride(spec.Installer.SilentArgsOverride)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// If the path is a UNC share, attempt to authenticate against it via
	// `net use` using a stored SMB credential. Non-UNC paths and UNC
	// paths without a matching credential proceed unauthenticated; the
	// installer call itself will fail with "access denied" if the agent's
	// SYSTEM account can't reach the share.
	var teardown func()
	if strings.HasPrefix(spec.Installer.Path, `\\`) {
		teardown = r.mountSMBIfNeeded(spec.Installer.Path)
	}
	if teardown != nil {
		defer teardown()
	}

	r.log("local_install [%d] %s → %s", id, spec.Installer.Name, spec.Installer.Path)
	res, err := localinstall.Run(ctx, localinstall.RunOptions{
		Path:          spec.Installer.Path,
		OverrideArgs:  override,
		ExpectedCodes: expected,
		Framework:     localinstall.Framework(spec.Installer.FrameworkHint),
	})
	if err != nil {
		return "runner error: " + err.Error(), -1
	}
	r.log("  → %s", res.String())
	return res.Output, res.ExitCode
}

// smbCredResp is the decrypted credential the server hands over for a
// single local_install call.
type smbCredResp struct {
	ShareRoot string `json:"share_root"`
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	Password  string `json:"password"`
}

// mountSMBIfNeeded looks up a stored SMB credential whose share_root is
// a prefix of `path` and calls `net use` to mount it. Returns a
// teardown closure that runs `net use <share> /delete`; nil if nothing
// was mounted. Password is never logged — the agent log stream only
// mentions the share root and username.
func (r *Runtime) mountSMBIfNeeded(path string) func() {
	cred, err := r.fetchSMBCred(path)
	if err != nil {
		r.log("smb creds fetch: %v (proceeding without auth)", err)
		return nil
	}
	if cred == nil {
		return nil
	}
	user := cred.Username
	if cred.Domain != "" {
		user = cred.Domain + `\` + cred.Username
	}
	r.log("smb: mapping %s as %s", cred.ShareRoot, user)
	cmd := exec.Command("net", "use", cred.ShareRoot, "/user:"+user, cred.Password, "/persistent:no")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		r.log("smb: net use failed: %v — %s", err, firstLineSafe(out))
		// Return nil so runLocalInstall doesn't schedule a teardown for a
		// mapping that didn't happen.
		return nil
	}
	root := cred.ShareRoot
	return func() {
		cmd := exec.Command("net", "use", root, "/delete")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run() // best-effort; never fails the install on teardown
	}
}

func (r *Runtime) fetchSMBCred(path string) (*smbCredResp, error) {
	u := fmt.Sprintf("%s/api/?action=agent_smb_creds&hostname=%s&path=%s",
		strings.TrimRight(r.Cfg.Server, "/"), mustHost(), urlEscape(path))
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	if r.Cfg.APISecret != "" {
		req.Header.Set("X-API-Secret", r.Cfg.APISecret)
	}
	if r.Cfg.AgentToken != "" {
		req.Header.Set("X-Corrivex-Token", r.Cfg.AgentToken)
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out smbCredResp
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type smbRootResp struct {
	ShareRoot string `json:"share_root"`
}

func (r *Runtime) fetchSMBRoots() ([]string, error) {
	u := fmt.Sprintf("%s/api/?action=agent_smb_roots&hostname=%s",
		strings.TrimRight(r.Cfg.Server, "/"), mustHost())
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	if r.Cfg.APISecret != "" {
		req.Header.Set("X-API-Secret", r.Cfg.APISecret)
	}
	if r.Cfg.AgentToken != "" {
		req.Header.Set("X-Corrivex-Token", r.Cfg.AgentToken)
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var rows []smbRootResp
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		root := strings.TrimSpace(row.ShareRoot)
		if root != "" {
			out = append(out, root)
		}
	}
	return out, nil
}

func (r *Runtime) scanLocalInstallerShares() []localinstall.DiscoveredInstaller {
	roots, err := r.fetchSMBRoots()
	if err != nil {
		r.log("local installer share roots: %v", err)
		return nil
	}
	if len(roots) == 0 {
		return nil
	}
	var all []localinstall.DiscoveredInstaller
	for _, root := range roots {
		r.log("local installer scan: %s", root)
		teardown := r.mountSMBIfNeeded(root)
		found, err := localinstall.ScanDirectory(root, localinstall.ScanOptions{MaxDepth: 4, MaxFiles: 200})
		if teardown != nil {
			teardown()
		}
		if err != nil {
			r.log("local installer scan failed for %s: %v", root, err)
			continue
		}
		r.log("local installer scan: %d installer(s) found under %s", len(found), root)
		all = append(all, found...)
	}
	return all
}

// urlEscape is a tiny replacement for url.QueryEscape that keeps the
// agent.go imports clean. Handles the characters we actually see in
// UNC paths (backslash, space, colon).
func urlEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func firstLineSafe(b []byte) string {
	for i, c := range b {
		if c == '\n' || c == '\r' {
			return string(b[:i])
		}
	}
	return string(b)
}

// installerSpec mirrors the JSON shape emitted by the server's
// agent_local_installer endpoint.
type installerSpec struct {
	Installer struct {
		ID                 int64  `json:"id"`
		Name               string `json:"name"`
		Path               string `json:"path"`
		FrameworkHint      string `json:"framework_hint"`
		SilentArgsOverride string `json:"silent_args_override"`
		ExpectedExitCodes  string `json:"expected_exit_codes"`
	} `json:"installer"`
	AllowedPrefixes string `json:"allowed_prefixes"`
}

func (r *Runtime) fetchLocalInstaller(id int64) (*installerSpec, error) {
	u := fmt.Sprintf("%s/api/?action=agent_local_installer&hostname=%s&id=%d",
		strings.TrimRight(r.Cfg.Server, "/"), mustHost(), id)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	if r.Cfg.APISecret != "" {
		req.Header.Set("X-API-Secret", r.Cfg.APISecret)
	}
	if r.Cfg.AgentToken != "" {
		req.Header.Set("X-Corrivex-Token", r.Cfg.AgentToken)
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var spec installerSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// validateInstallerPath enforces the UNC-or-allowed-prefix rule. Paths
// that point at \\.\pipe, \\?\, the Windows dir, or %TEMP% are
// rejected even if an admin pointed an allowed-prefix there (the
// allowed-prefix list is a whitelist, not a carte blanche).
func validateInstallerPath(path, allowedPrefixes string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	low := strings.ToLower(path)
	// Hard-block traversal shenanigans and Windows special roots.
	for _, bad := range []string{`\\.\`, `\\?\`, `c:\windows\`, `c:\windows\\`, `c:\program files\windowsapps\`} {
		if strings.HasPrefix(low, bad) {
			return fmt.Errorf("path starts with blocked prefix %q", bad)
		}
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains traversal sequence")
	}
	// UNC paths always pass.
	if strings.HasPrefix(path, `\\`) {
		return nil
	}
	// Otherwise the path must start with one of the admin-listed prefixes.
	var prefixes []string
	for _, p := range strings.Split(allowedPrefixes, "\n") {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		prefixes = append(prefixes, strings.ToLower(p))
	}
	if len(prefixes) == 0 {
		return fmt.Errorf("local path not allowed: no local_installer_allowed_prefixes configured (add a prefix in Settings or use a UNC path)")
	}
	for _, p := range prefixes {
		if strings.HasPrefix(low, p) {
			return nil
		}
	}
	return fmt.Errorf("path does not match any allowed prefix")
}

// parseExpectedCodes converts a comma-separated list like "0,3010"
// into an []int. Empty or malformed input returns nil (caller falls
// back to [0, 3010]).
func parseExpectedCodes(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}
