//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
