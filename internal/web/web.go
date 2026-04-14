// Package web renders the Corrivex dashboard and login page.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"

	"github.com/markov/corrivex/internal/auth"
	"github.com/markov/corrivex/internal/db"
	"github.com/markov/corrivex/internal/hub"
	"github.com/markov/corrivex/internal/version"
)

//go:embed templates/*.tmpl
var fs embed.FS

// Dashboard renders the main UI. Requests are either:
//   - authenticated session  → full dashboard
//   - no session, setup needed or not → redirect to /login
type Dashboard struct {
	DB  *db.DB
	Hub *hub.Hub
	tpl *template.Template
}

func NewDashboard(d *db.DB, h *hub.Hub) (*Dashboard, error) {
	tpl, err := template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		return nil, err
	}
	return &Dashboard{DB: d, Hub: h, tpl: tpl}, nil
}

func (h *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/login":
		h.renderLogin(w, r)
		return
	case "/", "/index.html":
		// fall through to dashboard render
	default:
		http.NotFound(w, r)
		return
	}

	// Must be signed in.
	user, ok := h.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var migrationError string
	if err := h.DB.Migrate(); err != nil {
		migrationError = err.Error()
	}

	domains, _ := h.DB.AllowedDomains()
	filterDom := r.URL.Query().Get("domain")
	pcs, _ := h.DB.AllPCs(filterDom)
	settings, _ := h.DB.AllSettings()
	// Decorate with current online state from the hub.
	if h.Hub != nil {
		online := h.Hub.OnlineHosts()
		for i := range pcs {
			pcs[i].Online = online[pcs[i].Hostname]
		}
	}

	var total, withUpdates, upToDate, neverSeen int
	total = len(pcs)
	for _, p := range pcs {
		wuCount := p.WindowsUpdateCount() // -1 means unknown
		switch {
		case p.UpdateCount > 0 || wuCount > 0:
			withUpdates++
		case p.UpdateCount == 0 && (wuCount == 0 || wuCount == -1):
			upToDate++
		}
		if p.LastFullReport == nil {
			neverSeen++
		}
	}

	schemaVersion := 0
	if versions, err := h.DB.SchemaVersions(); err == nil {
		for _, v := range versions {
			if v.Version > schemaVersion {
				schemaVersion = v.Version
			}
		}
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	apiURL := scheme + "://" + r.Host + "/api/"
	bootstrap := fmt.Sprintf(
		`powershell -NoProfile -ExecutionPolicy Bypass -Command "iex (iwr -UseBasicParsing ('%s?action=bootstrap&host='+$env:COMPUTERNAME+'&domain='+(Get-WmiObject Win32_ComputerSystem).Domain)).Content"`,
		apiURL)

	for k, def := range map[string]string{
		"check_interval_minutes":   "1",
		"full_scan_interval_hours": "24",
		"service_name":             "Corrivex Agent",
	} {
		if _, ok := settings[k]; !ok {
			settings[k] = def
		}
	}

	data := map[string]any{
		"MigrationError": migrationError,
		"Domains":        domains,
		"PCs":            pcs,
		"Settings":       settings,
		"Stats": map[string]int{
			"Total":       total,
			"WithUpdates": withUpdates,
			"UpToDate":    upToDate,
			"NeverSeen":   neverSeen,
		},
		"SchemaVersion": schemaVersion,
		"AppVersion":    version.Version,
		"BootstrapCmd":  bootstrap,
		"APIUrl":        apiURL,
		"CurrentUser": map[string]any{
			"username":     user.Username,
			"role":         user.Role,
			"totp_enabled": user.TOTPEnabled,
		},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	if err := h.tpl.ExecuteTemplate(w, "dashboard.html.tmpl", data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (h *Dashboard) renderLogin(w http.ResponseWriter, r *http.Request) {
	// If already signed in, bounce to /
	if _, ok := h.currentUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// ensure migrations (so users table exists)
	_ = h.DB.Migrate()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := h.tpl.ExecuteTemplate(w, "login.html.tmpl", nil); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (h *Dashboard) currentUser(r *http.Request) (*db.User, bool) {
	c, err := r.Cookie(auth.SessionCookieName)
	if err != nil || c.Value == "" {
		return nil, false
	}
	_, user, err := h.DB.LookupSession(c.Value)
	if err != nil || user == nil {
		return nil, false
	}
	return user, true
}
