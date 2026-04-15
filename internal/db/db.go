// Package db is the Corrivex data layer. It supports two backends:
// MariaDB/MySQL (the original target) and SQLite (single-file deployments,
// typical for Windows). Driver is chosen via Config.Driver.
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

// Driver picks the database backend.
type Driver string

const (
	DriverMaria  Driver = "mariadb"
	DriverSQLite Driver = "sqlite"
)

type Config struct {
	Driver Driver

	// MariaDB
	Host    string
	Port    int
	Name    string
	User    string
	Pass    string
	Charset string

	// SQLite — path to the .db file. Created if missing.
	Path string

	// Common
	Keep     int
	CheckDom bool
}

type DB struct {
	sql    *sql.DB
	cfg    Config
	driver Driver
	hostRe *regexp.Regexp
}

// DriverName returns which backend this connection uses.
func (d *DB) DriverName() Driver { return d.driver }

func Open(cfg Config) (*DB, error) {
	if cfg.Driver == "" {
		cfg.Driver = DriverMaria
	}
	switch cfg.Driver {
	case DriverMaria:
		return openMaria(cfg)
	case DriverSQLite:
		return openSQLite(cfg)
	default:
		return nil, fmt.Errorf("unknown db driver %q", cfg.Driver)
	}
}

func openMaria(cfg Config) (*DB, error) {
	if cfg.Charset == "" {
		cfg.Charset = "utf8mb4"
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=Local&multiStatements=true",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Name, cfg.Charset)
	sqldb, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := sqldb.Ping(); err != nil {
		// Try to create DB if missing
		rootDSN := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=%s&multiStatements=true",
			cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Charset)
		root, e2 := sql.Open("mysql", rootDSN)
		if e2 != nil {
			return nil, fmt.Errorf("connect: %w / bootstrap: %v", err, e2)
		}
		defer root.Close()
		if _, e3 := root.Exec("CREATE DATABASE IF NOT EXISTS `" + cfg.Name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); e3 != nil {
			return nil, fmt.Errorf("create db: %w", e3)
		}
		if err = sqldb.Ping(); err != nil {
			return nil, err
		}
	}
	sqldb.SetMaxOpenConns(20)
	sqldb.SetMaxIdleConns(5)
	sqldb.SetConnMaxLifetime(5 * time.Minute)
	return &DB{sql: sqldb, cfg: cfg, driver: DriverMaria, hostRe: regexp.MustCompile(`[^a-zA-Z0-9_\-\.]`)}, nil
}

func openSQLite(cfg Config) (*DB, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("sqlite: --db-path required")
	}
	if dir := filepath.Dir(cfg.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	dsn := cfg.Path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_time_format=sqlite"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := sqldb.Ping(); err != nil {
		return nil, err
	}
	// Serialize writes — SQLite has one writer at a time even in WAL.
	sqldb.SetMaxOpenConns(8)
	sqldb.SetMaxIdleConns(2)
	sqldb.SetConnMaxLifetime(0)
	return &DB{sql: sqldb, cfg: cfg, driver: DriverSQLite, hostRe: regexp.MustCompile(`[^a-zA-Z0-9_\-\.]`)}, nil
}

func (d *DB) Close() error { return d.sql.Close() }
func (d *DB) SQL() *sql.DB { return d.sql }
func (d *DB) NormalizeHost(h string) string {
	return strings.ToUpper(d.hostRe.ReplaceAllString(strings.TrimSpace(h), "_"))
}

// -- Migrations -------------------------------------------------------------

var migrations = []struct {
	Version     int
	Description string
	Statements  []string
}{
	{1, "Initial schema", []string{
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INT NOT NULL,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			description VARCHAR(255) NOT NULL DEFAULT ''
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS pcs (
			id INT NOT NULL AUTO_INCREMENT,
			hostname VARCHAR(255) NOT NULL,
			last_seen DATETIME NULL,
			update_count INT NOT NULL DEFAULT -1,
			last_check_at DATETIME NULL,
			last_upgrade_at DATETIME NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uq_hostname (hostname)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS reports (
			id BIGINT NOT NULL AUTO_INCREMENT,
			hostname VARCHAR(255) NOT NULL,
			action ENUM('check','upgrade','full_report','post_task_report','unknown') NOT NULL DEFAULT 'unknown',
			reported_at DATETIME NOT NULL,
			username VARCHAR(255) NULL,
			ip VARCHAR(45) NULL,
			output LONGTEXT NULL,
			packages LONGTEXT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_hostname (hostname),
			KEY idx_action (action),
			KEY idx_host_action (hostname, action, reported_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}},
	{2, "Structured packages JSON", []string{
		`ALTER TABLE reports ADD COLUMN IF NOT EXISTS packages LONGTEXT NULL`,
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS last_packages LONGTEXT NULL`,
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS last_exported LONGTEXT NULL`,
	}},
	{3, "Domains, tasks, system info", []string{
		`CREATE TABLE IF NOT EXISTS allowed_domains (
			id INT NOT NULL AUTO_INCREMENT,
			domain VARCHAR(255) NOT NULL,
			notes VARCHAR(500) NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY uq_domain (domain)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id BIGINT NOT NULL AUTO_INCREMENT,
			hostname VARCHAR(255) NOT NULL,
			type ENUM('upgrade_all','upgrade_package','check') NOT NULL DEFAULT 'check',
			package_id VARCHAR(255) NULL,
			package_name VARCHAR(500) NULL,
			status ENUM('pending','delivered','completed','failed') NOT NULL DEFAULT 'pending',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			delivered_at DATETIME NULL,
			completed_at DATETIME NULL,
			result TEXT NULL,
			PRIMARY KEY (id),
			KEY idx_host_status (hostname, status)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS domain VARCHAR(255) NULL`,
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS os_version VARCHAR(255) NULL`,
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS users LONGTEXT NULL`,
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS local_admins LONGTEXT NULL`,
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS last_full_report DATETIME NULL`,
	}},
	{4, "Fix reports.action ENUM", []string{
		`ALTER TABLE reports MODIFY COLUMN action ENUM('check','upgrade','full_report','post_task_report','unknown') NOT NULL DEFAULT 'unknown'`,
		`ALTER TABLE reports ADD COLUMN IF NOT EXISTS output LONGTEXT NULL`,
	}},
	{5, "Settings, package cache, install_package task", []string{
		`CREATE TABLE IF NOT EXISTS settings (
			key_name VARCHAR(100) NOT NULL,
			value TEXT NULL,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (key_name)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS package_cache (
			id INT NOT NULL AUTO_INCREMENT,
			query VARCHAR(255) NOT NULL,
			results LONGTEXT NULL,
			cached_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY uq_query (query)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`ALTER TABLE tasks MODIFY COLUMN type ENUM('upgrade_all','upgrade_package','install_package','uninstall_package','check') NOT NULL DEFAULT 'check'`,
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS package_version VARCHAR(100) NULL AFTER package_name`,
		`INSERT IGNORE INTO settings (key_name, value) VALUES
			('check_interval_minutes',  '1'),
			('full_scan_interval_hours','24'),
			('install_service',         'true'),
			('service_name',            'Corrivex Agent')`,
	}},
	{6, "Ping every 1 min, full scan every 24h", []string{
		`INSERT IGNORE INTO settings (key_name, value) VALUES ('full_scan_interval_hours','24')`,
		`UPDATE settings SET value='1' WHERE key_name='check_interval_minutes' AND value='60'`,
	}},
	{7, "Per-agent token + uninstall_self task", []string{
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS token CHAR(64) NULL`,
		`ALTER TABLE tasks MODIFY COLUMN type ENUM('upgrade_all','upgrade_package','install_package','uninstall_package','check','uninstall_self') NOT NULL DEFAULT 'check'`,
	}},
	{8, "Users, sessions, roles", []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT NOT NULL AUTO_INCREMENT,
			username VARCHAR(100) NOT NULL,
			password_hash VARCHAR(200) NOT NULL,
			role ENUM('admin','operator','viewer') NOT NULL DEFAULT 'viewer',
			totp_secret VARCHAR(64) NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login_at DATETIME NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uq_username (username)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id CHAR(64) NOT NULL,
			user_id INT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			last_seen_at DATETIME NULL,
			ip VARCHAR(45) NULL,
			user_agent VARCHAR(500) NULL,
			PRIMARY KEY (id),
			KEY idx_user (user_id),
			KEY idx_exp (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}},
	{9, "Windows Update inventory + task types", []string{
		`ALTER TABLE pcs ADD COLUMN IF NOT EXISTS windows_updates LONGTEXT NULL`,
		`ALTER TABLE tasks MODIFY COLUMN type ENUM('upgrade_all','upgrade_package','install_package','uninstall_package','check','uninstall_self','windows_update_all','windows_update_single') NOT NULL DEFAULT 'check'`,
	}},
	{10, "Per-host installed-software inventory + history", []string{
		`CREATE TABLE IF NOT EXISTS installed_software (
			id BIGINT NOT NULL AUTO_INCREMENT,
			hostname VARCHAR(255) NOT NULL,
			package_id VARCHAR(255) NOT NULL,
			package_name VARCHAR(500) NULL,
			version VARCHAR(200) NULL,
			source VARCHAR(50) NULL,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY uq_host_pkg (hostname, package_id),
			KEY idx_inst_hostname (hostname)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS installed_software_history (
			id BIGINT NOT NULL AUTO_INCREMENT,
			hostname VARCHAR(255) NOT NULL,
			package_id VARCHAR(255) NOT NULL,
			package_name VARCHAR(500) NULL,
			old_version VARCHAR(200) NULL,
			new_version VARCHAR(200) NULL,
			change_type ENUM('installed','updated','removed') NOT NULL,
			detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_hist_host_pkg (hostname, package_id),
			KEY idx_hist_host_time (hostname, detected_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}},
	{11, "CVE scan cache + CISA KEV catalog", []string{
		`CREATE TABLE IF NOT EXISTS cve_cache (
			package_id VARCHAR(255) NOT NULL,
			version VARCHAR(200) NOT NULL,
			source VARCHAR(20) NOT NULL DEFAULT 'none',
			cves_json LONGTEXT NULL,
			scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (package_id, version),
			KEY idx_cve_scanned (scanned_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS cve_kev (
			cve_id VARCHAR(30) NOT NULL,
			vendor VARCHAR(255) NULL,
			product VARCHAR(255) NULL,
			vulnerability_name VARCHAR(500) NULL,
			date_added DATE NULL,
			short_description TEXT NULL,
			synced_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (cve_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`INSERT IGNORE INTO settings (key_name, value) VALUES
			('cve_scan_interval_hours', '6'),
			('cve_cache_ttl_hours',     '24'),
			('cve_winget_cpe_map',      '')`,
	}},
}

func (d *DB) Migrate() error {
	mig := migrations
	existsQ := "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='schema_version'"
	if d.driver == DriverSQLite {
		mig = migrationsSQLite
		existsQ = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'"
	}
	var exists int
	if err := d.sql.QueryRow(existsQ).Scan(&exists); err != nil {
		return err
	}
	var current int
	if exists > 0 {
		if err := d.sql.QueryRow("SELECT COALESCE(MAX(version),0) FROM schema_version").Scan(&current); err != nil {
			return err
		}
	}
	for _, m := range mig {
		if m.Version <= current {
			continue
		}
		tx, err := d.sql.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range m.Statements {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration v%d failed: %w", m.Version, err)
			}
		}
		if _, err := tx.Exec("INSERT INTO schema_version (version, description) VALUES (?,?)", m.Version, m.Description); err != nil {
			tx.Rollback()
			return fmt.Errorf("record v%d: %w", m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// migrationsSQLite mirrors the MariaDB schema using SQLite-friendly DDL.
// Numbering is kept in lock-step so SchemaVersion() returns the same value
// regardless of backend.
var migrationsSQLite = []struct {
	Version     int
	Description string
	Statements  []string
}{
	{1, "Initial schema", []string{
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			description TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS pcs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL UNIQUE,
			last_seen DATETIME,
			update_count INTEGER NOT NULL DEFAULT -1,
			last_check_at DATETIME,
			last_upgrade_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS reports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL,
			action TEXT NOT NULL DEFAULT 'unknown' CHECK (action IN ('check','upgrade','full_report','post_task_report','unknown')),
			reported_at DATETIME NOT NULL,
			username TEXT,
			ip TEXT,
			output TEXT,
			packages TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_reports_hostname ON reports(hostname)`,
		`CREATE INDEX IF NOT EXISTS idx_reports_action ON reports(action)`,
		`CREATE INDEX IF NOT EXISTS idx_reports_host_action ON reports(hostname, action, reported_at)`,
	}},
	{2, "Structured packages JSON", []string{
		// Columns already present from v1 in SQLite; add the per-PC last_packages/last_exported.
		`ALTER TABLE pcs ADD COLUMN last_packages TEXT`,
		`ALTER TABLE pcs ADD COLUMN last_exported TEXT`,
	}},
	{3, "Domains, tasks, system info", []string{
		`CREATE TABLE IF NOT EXISTS allowed_domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL UNIQUE,
			notes TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'check' CHECK (type IN ('upgrade_all','upgrade_package','install_package','uninstall_package','check','uninstall_self','windows_update_all','windows_update_single')),
			package_id TEXT,
			package_name TEXT,
			package_version TEXT,
			status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','completed','failed')),
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			delivered_at DATETIME,
			completed_at DATETIME,
			result TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_host_status ON tasks(hostname, status)`,
		`ALTER TABLE pcs ADD COLUMN domain TEXT`,
		`ALTER TABLE pcs ADD COLUMN os_version TEXT`,
		`ALTER TABLE pcs ADD COLUMN users TEXT`,
		`ALTER TABLE pcs ADD COLUMN local_admins TEXT`,
		`ALTER TABLE pcs ADD COLUMN last_full_report DATETIME`,
	}},
	{4, "Fix reports.action ENUM", []string{
		// In SQLite the v1 CHECK already allowed all variants; nothing to alter.
		// If `output` is missing on a very old database, this is a no-op given v1 created it.
	}},
	{5, "Settings, package cache, install_package task", []string{
		`CREATE TABLE IF NOT EXISTS settings (
			key_name TEXT NOT NULL PRIMARY KEY,
			value TEXT,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS package_cache (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			query TEXT NOT NULL UNIQUE,
			results TEXT,
			cached_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT OR IGNORE INTO settings (key_name, value) VALUES ('check_interval_minutes','1')`,
		`INSERT OR IGNORE INTO settings (key_name, value) VALUES ('full_scan_interval_hours','24')`,
		`INSERT OR IGNORE INTO settings (key_name, value) VALUES ('install_service','true')`,
		`INSERT OR IGNORE INTO settings (key_name, value) VALUES ('service_name','Corrivex Agent')`,
	}},
	{6, "Ping every 1 min, full scan every 24h", []string{
		`INSERT OR IGNORE INTO settings (key_name, value) VALUES ('full_scan_interval_hours','24')`,
		`UPDATE settings SET value='1' WHERE key_name='check_interval_minutes' AND value='60'`,
	}},
	{7, "Per-agent token + uninstall_self task", []string{
		`ALTER TABLE pcs ADD COLUMN token TEXT`,
	}},
	{8, "Users, sessions, roles", []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','operator','viewer')),
			totp_secret TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT NOT NULL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			last_seen_at DATETIME,
			ip TEXT,
			user_agent TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)`,
	}},
	{9, "Windows Update inventory + task types", []string{
		`ALTER TABLE pcs ADD COLUMN windows_updates TEXT`,
		// The CHECK on tasks.type from v3 already covers windows_update_*.
	}},
	{10, "Per-host installed-software inventory + history", []string{
		`CREATE TABLE IF NOT EXISTS installed_software (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL,
			package_id TEXT NOT NULL,
			package_name TEXT,
			version TEXT,
			source TEXT,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (hostname, package_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_inst_hostname ON installed_software(hostname)`,
		`CREATE TABLE IF NOT EXISTS installed_software_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL,
			package_id TEXT NOT NULL,
			package_name TEXT,
			old_version TEXT,
			new_version TEXT,
			change_type TEXT NOT NULL CHECK (change_type IN ('installed','updated','removed')),
			detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hist_host_pkg ON installed_software_history(hostname, package_id)`,
		`CREATE INDEX IF NOT EXISTS idx_hist_host_time ON installed_software_history(hostname, detected_at)`,
	}},
	{11, "CVE scan cache + CISA KEV catalog", []string{
		`CREATE TABLE IF NOT EXISTS cve_cache (
			package_id TEXT NOT NULL,
			version TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT 'none',
			cves_json TEXT,
			scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (package_id, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cve_scanned ON cve_cache(scanned_at)`,
		`CREATE TABLE IF NOT EXISTS cve_kev (
			cve_id TEXT NOT NULL PRIMARY KEY,
			vendor TEXT,
			product TEXT,
			vulnerability_name TEXT,
			date_added DATE,
			short_description TEXT,
			synced_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT OR IGNORE INTO settings (key_name, value) VALUES
			('cve_scan_interval_hours', '6'),
			('cve_cache_ttl_hours',     '24'),
			('cve_winget_cpe_map',      '')`,
	}},
}

type SchemaVersion struct {
	Version     int       `json:"version"`
	AppliedAt   time.Time `json:"applied_at"`
	Description string    `json:"description"`
}

func (d *DB) SchemaVersions() ([]SchemaVersion, error) {
	rows, err := d.sql.Query("SELECT version, applied_at, description FROM schema_version ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SchemaVersion
	for rows.Next() {
		var s SchemaVersion
		if err := rows.Scan(&s.Version, &s.AppliedAt, &s.Description); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// -- Domains ----------------------------------------------------------------

type Domain struct {
	ID        int       `json:"id"`
	Domain    string    `json:"domain"`
	Notes     *string   `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
}

func (d *DB) IsDomainAllowed(domain string) (bool, error) {
	if !d.cfg.CheckDom {
		return true, nil
	}
	// Wildcard short-circuit: a single literal '*' row in allowed_domains
	// means "any domain (including empty) is permitted to enroll" — useful
	// for closed networks where the dashboard is the only access control.
	var hasWild int
	if err := d.sql.QueryRow("SELECT COUNT(*) FROM allowed_domains WHERE domain='*'").Scan(&hasWild); err != nil {
		return false, err
	}
	if hasWild > 0 {
		return true, nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false, nil
	}
	var n int
	err := d.sql.QueryRow("SELECT COUNT(*) FROM allowed_domains WHERE LOWER(domain)=?", domain).Scan(&n)
	return n > 0, err
}

func (d *DB) AllowedDomains() ([]Domain, error) {
	rows, err := d.sql.Query("SELECT id, domain, notes, created_at FROM allowed_domains ORDER BY domain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var x Domain
		if err := rows.Scan(&x.ID, &x.Domain, &x.Notes, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (d *DB) AddAllowedDomain(domain, notes string) error {
	verb := "INSERT IGNORE"
	if d.driver == DriverSQLite {
		verb = "INSERT OR IGNORE"
	}
	_, err := d.sql.Exec(verb+" INTO allowed_domains (domain, notes) VALUES (?,?)",
		strings.ToLower(strings.TrimSpace(domain)), notes)
	return err
}

func (d *DB) RemoveAllowedDomain(id int) error {
	_, err := d.sql.Exec("DELETE FROM allowed_domains WHERE id=?", id)
	return err
}

// -- Tasks ------------------------------------------------------------------

type Task struct {
	ID             int64          `json:"id"`
	Hostname       string         `json:"hostname"`
	Type           string         `json:"type"`
	PackageID      *string        `json:"package_id"`
	PackageName    *string        `json:"package_name"`
	PackageVersion *string        `json:"package_version"`
	Status         string         `json:"status"`
	CreatedAt      time.Time      `json:"created_at"`
	DeliveredAt    *time.Time     `json:"delivered_at"`
	CompletedAt    *time.Time     `json:"completed_at"`
	Result         *string        `json:"result"`
}

func (d *DB) CreateTask(hostname, typ string, pkgID, pkgName, pkgVer *string) (int64, error) {
	if typ == "upgrade_all" {
		d.sql.Exec(
			"UPDATE tasks SET status='failed', result='superseded' WHERE hostname=? AND type='upgrade_all' AND status='pending'",
			hostname)
	} else if typ == "upgrade_package" && pkgID != nil {
		d.sql.Exec(
			"UPDATE tasks SET status='failed', result='superseded' WHERE hostname=? AND type='upgrade_package' AND package_id=? AND status='pending'",
			hostname, *pkgID)
	}
	res, err := d.sql.Exec(
		"INSERT INTO tasks (hostname, type, package_id, package_name, package_version) VALUES (?,?,?,?,?)",
		hostname, typ, nullStr(pkgID), nullStr(pkgName), nullStr(pkgVer))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) PendingTasks(hostname string) ([]Task, error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(
		"SELECT id, hostname, type, package_id, package_name, package_version, status, created_at, delivered_at, completed_at, result FROM tasks WHERE hostname=? AND status='pending' ORDER BY created_at",
		hostname)
	if err != nil {
		return nil, err
	}
	var out []Task
	var ids []int64
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Hostname, &t.Type, &t.PackageID, &t.PackageName, &t.PackageVersion, &t.Status, &t.CreatedAt, &t.DeliveredAt, &t.CompletedAt, &t.Result); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, t)
		ids = append(ids, t.ID)
	}
	rows.Close()
	if len(ids) > 0 {
		placeholders := strings.Repeat("?,", len(ids))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]any, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		if _, err := tx.Exec("UPDATE tasks SET status='delivered', delivered_at=CURRENT_TIMESTAMP WHERE id IN ("+placeholders+")", args...); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

func (d *DB) CompleteTask(id int64, result string) error {
	_, err := d.sql.Exec("UPDATE tasks SET status='completed', completed_at=CURRENT_TIMESTAMP, result=? WHERE id=?", result, id)
	return err
}

// MarkTaskDelivered is used when the server pushes a task straight to a live
// agent via the persistent WS connection, so the dashboard does not need to
// wait for the next poll to see the 'delivered' transition.
func (d *DB) MarkTaskDelivered(id int64) error {
	_, err := d.sql.Exec("UPDATE tasks SET status='delivered', delivered_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'", id)
	return err
}

func (d *DB) TasksForHost(hostname string, limit int) ([]Task, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := d.sql.Query(
		"SELECT id, hostname, type, package_id, package_name, package_version, status, created_at, delivered_at, completed_at, result FROM tasks WHERE hostname=? ORDER BY created_at DESC LIMIT ?",
		hostname, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Hostname, &t.Type, &t.PackageID, &t.PackageName, &t.PackageVersion, &t.Status, &t.CreatedAt, &t.DeliveredAt, &t.CompletedAt, &t.Result); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// -- Reports ----------------------------------------------------------------

type FullReport struct {
	Hostname          string           `json:"hostname"`
	Host              string           `json:"host"`
	Action            string           `json:"action"`
	Timestamp         string           `json:"timestamp"`
	Username          string           `json:"username"`
	User              string           `json:"user"`
	Domain            string           `json:"domain"`
	OSVersion         string           `json:"os_version"`
	Users             []map[string]any `json:"users"`
	LocalAdmins       []map[string]any `json:"local_admins"`
	Packages          []map[string]any `json:"packages"`
	WindowsUpdates    []map[string]any `json:"windows_updates"`
	InstalledSoftware []map[string]any `json:"installed_software"`
	UpdateCount       *int             `json:"update_count"`
	AgentLog          string           `json:"agent_log"`
}

func (d *DB) StoreFullReport(r FullReport, clientIP string) ([]Task, error) {
	host := r.Hostname
	if host == "" {
		host = r.Host
	}
	hostname := d.NormalizeHost(host)
	if hostname == "" {
		return nil, fmt.Errorf("missing hostname")
	}
	action := r.Action
	if action == "" {
		action = "full_report"
	}
	user := r.Username
	if user == "" {
		user = r.User
	}
	domain := strings.ToLower(strings.TrimSpace(r.Domain))

	var packagesJSON, usersJSON, adminsJSON, windowsJSON *string
	if r.Packages != nil {
		b, _ := json.Marshal(r.Packages)
		s := string(b)
		packagesJSON = &s
	}
	if r.Users != nil {
		b, _ := json.Marshal(r.Users)
		s := string(b)
		usersJSON = &s
	}
	if r.LocalAdmins != nil {
		b, _ := json.Marshal(r.LocalAdmins)
		s := string(b)
		adminsJSON = &s
	}
	if r.WindowsUpdates != nil {
		b, _ := json.Marshal(r.WindowsUpdates)
		s := string(b)
		windowsJSON = &s
	}
	updateCount := -1
	if r.Packages != nil {
		updateCount = len(r.Packages)
	} else if r.UpdateCount != nil {
		updateCount = *r.UpdateCount
	}

	if _, err := d.sql.Exec(
		"INSERT INTO reports (hostname, action, reported_at, username, ip, packages, output) VALUES (?,?,CURRENT_TIMESTAMP,?,?,?,?)",
		hostname, action, nullIfEmpty(user), nullIfEmpty(clientIP), packagesJSON, nullIfEmpty(r.AgentLog),
	); err != nil {
		return nil, err
	}

	isFull := "0"
	if action == "full_report" {
		isFull = "1"
	}
	var upsertSQL string
	if d.driver == DriverSQLite {
		upsertSQL = `
		INSERT INTO pcs (hostname, domain, os_version, last_seen, update_count, last_check_at, last_packages, users, local_admins, windows_updates, last_full_report)
		VALUES (?,?,?,CURRENT_TIMESTAMP,?,CURRENT_TIMESTAMP,?,?,?,?, CASE WHEN ?='1' THEN CURRENT_TIMESTAMP ELSE NULL END)
		ON CONFLICT(hostname) DO UPDATE SET
			domain           = COALESCE(excluded.domain, pcs.domain),
			os_version       = COALESCE(excluded.os_version, pcs.os_version),
			last_seen        = CURRENT_TIMESTAMP,
			update_count     = CASE WHEN excluded.update_count>=0 THEN excluded.update_count ELSE pcs.update_count END,
			last_check_at    = CASE WHEN excluded.update_count>=0 THEN CURRENT_TIMESTAMP ELSE pcs.last_check_at END,
			last_packages    = COALESCE(excluded.last_packages, pcs.last_packages),
			users            = COALESCE(excluded.users, pcs.users),
			local_admins     = COALESCE(excluded.local_admins, pcs.local_admins),
			windows_updates  = COALESCE(excluded.windows_updates, pcs.windows_updates),
			last_full_report = CASE WHEN ?='1' THEN CURRENT_TIMESTAMP ELSE pcs.last_full_report END`
	} else {
		upsertSQL = `
		INSERT INTO pcs (hostname, domain, os_version, last_seen, update_count, last_check_at, last_packages, users, local_admins, windows_updates, last_full_report)
		VALUES (?,?,?,CURRENT_TIMESTAMP,?,CURRENT_TIMESTAMP,?,?,?,?, IF(?='1', CURRENT_TIMESTAMP, NULL))
		ON DUPLICATE KEY UPDATE
			domain           = COALESCE(VALUES(domain), domain),
			os_version       = COALESCE(VALUES(os_version), os_version),
			last_seen        = CURRENT_TIMESTAMP,
			update_count     = IF(VALUES(update_count)>=0, VALUES(update_count), update_count),
			last_check_at    = IF(VALUES(update_count)>=0, CURRENT_TIMESTAMP, last_check_at),
			last_packages    = COALESCE(VALUES(last_packages), last_packages),
			users            = COALESCE(VALUES(users), users),
			local_admins     = COALESCE(VALUES(local_admins), local_admins),
			windows_updates  = COALESCE(VALUES(windows_updates), windows_updates),
			last_full_report = IF(?='1', CURRENT_TIMESTAMP, last_full_report)`
	}
	if _, err := d.sql.Exec(upsertSQL,
		hostname, nullIfEmpty(domain), nullIfEmpty(r.OSVersion), updateCount,
		packagesJSON, usersJSON, adminsJSON, windowsJSON, isFull, isFull,
	); err != nil {
		return nil, err
	}

	d.pruneReports(hostname, action)

	// Inventory + history sync. Only on full_report (post_task_report
	// doesn't carry the full installed list — it's a delta-style update).
	if action == "full_report" && r.InstalledSoftware != nil {
		_ = d.SyncInstalledSoftware(hostname, r.InstalledSoftware)
	}

	return d.PendingTasks(hostname)
}

func (d *DB) pruneReports(hostname, action string) {
	keep := d.cfg.Keep
	if keep <= 0 {
		keep = 50
	}
	d.sql.Exec(`
		DELETE FROM reports WHERE hostname=? AND action=?
		AND id NOT IN (SELECT id FROM (
			SELECT id FROM reports WHERE hostname=? AND action=? ORDER BY reported_at DESC LIMIT ?
		) sub)`,
		hostname, action, hostname, action, keep)
}

// -- PC queries -------------------------------------------------------------

type PC struct {
	ID             int             `json:"id"`
	Hostname       string          `json:"hostname"`
	Domain         *string         `json:"domain"`
	OSVersion      *string         `json:"os_version"`
	LastSeen       *time.Time      `json:"last_seen"`
	UpdateCount    int             `json:"update_count"`
	LastCheckAt    *time.Time      `json:"last_check_at"`
	LastUpgradeAt  *time.Time      `json:"last_upgrade_at"`
	LastFullReport *time.Time      `json:"last_full_report"`
	LastPackages   json.RawMessage `json:"last_packages,omitempty"`
	WindowsUpdates json.RawMessage `json:"windows_updates,omitempty"`
	Users          json.RawMessage `json:"users,omitempty"`
	LocalAdmins    json.RawMessage `json:"local_admins,omitempty"`
	CheckAt        *time.Time      `json:"check_at,omitempty"`
	CheckUser      *string         `json:"check_user,omitempty"`
	CheckIP        *string         `json:"check_ip,omitempty"`
	UpgradeAt      *time.Time      `json:"upgrade_at,omitempty"`
	UpgradeUser    *string         `json:"upgrade_user,omitempty"`
	Tasks          []Task          `json:"tasks,omitempty"`
	// Online is not persisted — the API/web layer fills it based on whether
	// the host currently has a live agent WebSocket connection.
	Online bool `json:"online"`
}

// WindowsUpdateCount parses the stored windows_updates JSON and returns the
// number of pending updates. Returns -1 when no scan has been recorded yet
// so the dashboard can render "unknown" instead of "0".
func (p PC) WindowsUpdateCount() int {
	raw := string(p.WindowsUpdates)
	if raw == "" || raw == "null" {
		return -1
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(p.WindowsUpdates, &arr); err != nil {
		return -1
	}
	return len(arr)
}

func (d *DB) AllPCs(filterDomain string) ([]PC, error) {
	q := `
		SELECT p.id, p.hostname, p.domain, p.os_version, p.last_seen, p.update_count,
			p.last_check_at, p.last_upgrade_at, p.last_full_report, p.last_packages, p.users, p.local_admins,
			p.windows_updates,
			rc.reported_at, rc.username, rc.ip,
			ru.reported_at, ru.username
		FROM pcs p
		LEFT JOIN reports rc ON rc.id=(SELECT id FROM reports WHERE hostname=p.hostname AND action IN('full_report','check','post_task_report') ORDER BY reported_at DESC LIMIT 1)
		LEFT JOIN reports ru ON ru.id=(SELECT id FROM reports WHERE hostname=p.hostname AND action IN('upgrade_all','upgrade_package') ORDER BY reported_at DESC LIMIT 1)`
	args := []any{}
	if filterDomain != "" {
		q += " WHERE LOWER(p.domain)=?"
		args = append(args, strings.ToLower(filterDomain))
	}
	q += " ORDER BY p.last_seen DESC"
	rows, err := d.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PC
	for rows.Next() {
		var p PC
		var pkgs, users, admins, wu sql.NullString
		if err := rows.Scan(&p.ID, &p.Hostname, &p.Domain, &p.OSVersion, &p.LastSeen, &p.UpdateCount,
			&p.LastCheckAt, &p.LastUpgradeAt, &p.LastFullReport, &pkgs, &users, &admins, &wu,
			&p.CheckAt, &p.CheckUser, &p.CheckIP,
			&p.UpgradeAt, &p.UpgradeUser); err != nil {
			return nil, err
		}
		if pkgs.Valid {
			p.LastPackages = json.RawMessage(pkgs.String)
		}
		if users.Valid {
			p.Users = json.RawMessage(users.String)
		}
		if admins.Valid {
			p.LocalAdmins = json.RawMessage(admins.String)
		}
		if wu.Valid {
			p.WindowsUpdates = json.RawMessage(wu.String)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) GetPC(hostname string) (*PC, error) {
	hostname = d.NormalizeHost(hostname)
	row := d.sql.QueryRow(
		"SELECT id, hostname, domain, os_version, last_seen, update_count, last_check_at, last_upgrade_at, last_full_report, last_packages, users, local_admins, windows_updates FROM pcs WHERE hostname=?",
		hostname)
	var p PC
	var pkgs, users, admins, wu sql.NullString
	if err := row.Scan(&p.ID, &p.Hostname, &p.Domain, &p.OSVersion, &p.LastSeen, &p.UpdateCount,
		&p.LastCheckAt, &p.LastUpgradeAt, &p.LastFullReport, &pkgs, &users, &admins, &wu); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if pkgs.Valid {
		p.LastPackages = json.RawMessage(pkgs.String)
	}
	if users.Valid {
		p.Users = json.RawMessage(users.String)
	}
	if admins.Valid {
		p.LocalAdmins = json.RawMessage(admins.String)
	}
	if wu.Valid {
		p.WindowsUpdates = json.RawMessage(wu.String)
	}
	tasks, err := d.TasksForHost(hostname, 30)
	if err != nil {
		return nil, err
	}
	p.Tasks = tasks
	return &p, nil
}

func (d *DB) TouchLastSeen(hostname string) error {
	q := "INSERT INTO pcs (hostname, last_seen) VALUES (?, CURRENT_TIMESTAMP) ON DUPLICATE KEY UPDATE last_seen=CURRENT_TIMESTAMP"
	if d.driver == DriverSQLite {
		q = "INSERT INTO pcs (hostname, last_seen) VALUES (?, CURRENT_TIMESTAMP) ON CONFLICT(hostname) DO UPDATE SET last_seen=CURRENT_TIMESTAMP"
	}
	_, err := d.sql.Exec(q, hostname)
	return err
}

// GetAgentToken returns the stored per-agent token for a hostname, or ""
// if none is set (including when the pcs row does not exist yet).
func (d *DB) GetAgentToken(hostname string) (string, error) {
	var t sql.NullString
	err := d.sql.QueryRow("SELECT token FROM pcs WHERE hostname=?", hostname).Scan(&t)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !t.Valid {
		return "", nil
	}
	return t.String, nil
}

// SetAgentToken upserts the token for a hostname (creates the pcs row if needed).
func (d *DB) SetAgentToken(hostname, token string) error {
	q := "INSERT INTO pcs (hostname, token, last_seen) VALUES (?,?,CURRENT_TIMESTAMP) ON DUPLICATE KEY UPDATE token=VALUES(token)"
	if d.driver == DriverSQLite {
		q = "INSERT INTO pcs (hostname, token, last_seen) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(hostname) DO UPDATE SET token=excluded.token"
	}
	_, err := d.sql.Exec(q, hostname, token)
	return err
}

// DeletePC hard-removes a host and all its related tasks/reports + the
// installed-software inventory and its history.
func (d *DB) DeletePC(hostname string) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		"DELETE FROM tasks WHERE hostname=?",
		"DELETE FROM reports WHERE hostname=?",
		"DELETE FROM installed_software WHERE hostname=?",
		"DELETE FROM installed_software_history WHERE hostname=?",
		"DELETE FROM pcs WHERE hostname=?",
	} {
		if _, err := tx.Exec(stmt, hostname); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetTask fetches one task by id.
func (d *DB) GetTask(id int64) (*Task, error) {
	row := d.sql.QueryRow(
		"SELECT id, hostname, type, package_id, package_name, package_version, status, created_at, delivered_at, completed_at, result FROM tasks WHERE id=?",
		id)
	var t Task
	if err := row.Scan(&t.ID, &t.Hostname, &t.Type, &t.PackageID, &t.PackageName, &t.PackageVersion, &t.Status, &t.CreatedAt, &t.DeliveredAt, &t.CompletedAt, &t.Result); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// -- Settings ---------------------------------------------------------------

func (d *DB) Setting(key, def string) string {
	var v sql.NullString
	if err := d.sql.QueryRow("SELECT value FROM settings WHERE key_name=?", key).Scan(&v); err != nil {
		return def
	}
	if !v.Valid {
		return def
	}
	return v.String
}

func (d *DB) SetSetting(key, val string) error {
	q := "INSERT INTO settings (key_name, value) VALUES (?,?) ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=CURRENT_TIMESTAMP"
	if d.driver == DriverSQLite {
		q = "INSERT INTO settings (key_name, value) VALUES (?,?) ON CONFLICT(key_name) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP"
	}
	_, err := d.sql.Exec(q, key, val)
	return err
}

func (d *DB) AllSettings() (map[string]string, error) {
	rows, err := d.sql.Query("SELECT key_name, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k string
		var v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		if v.Valid {
			out[k] = v.String
		} else {
			out[k] = ""
		}
	}
	return out, rows.Err()
}

// -- Package cache ----------------------------------------------------------

func (d *DB) PackageCacheGet(query string) (json.RawMessage, bool) {
	q := strings.ToLower(strings.TrimSpace(query))
	var results sql.NullString
	var cachedAt time.Time
	if err := d.sql.QueryRow("SELECT results, cached_at FROM package_cache WHERE query=?", q).
		Scan(&results, &cachedAt); err != nil {
		return nil, false
	}
	if time.Since(cachedAt) > 24*time.Hour {
		return nil, false
	}
	if !results.Valid {
		return nil, false
	}
	return json.RawMessage(results.String), true
}

func (d *DB) PackageCacheSet(query string, results []byte) {
	q := strings.ToLower(strings.TrimSpace(query))
	stmt := "INSERT INTO package_cache (query, results) VALUES (?,?) ON DUPLICATE KEY UPDATE results=VALUES(results), cached_at=CURRENT_TIMESTAMP"
	if d.driver == DriverSQLite {
		stmt = "INSERT INTO package_cache (query, results) VALUES (?,?) ON CONFLICT(query) DO UPDATE SET results=excluded.results, cached_at=CURRENT_TIMESTAMP"
	}
	d.sql.Exec(stmt, q, string(results))
}

// -- Installed-software inventory ------------------------------------------

// InstalledSoftware is the current snapshot row for one host+package pair.
type InstalledSoftware struct {
	Hostname    string    `json:"hostname"`
	PackageID   string    `json:"id"`
	PackageName string    `json:"name"`
	Version     string    `json:"version"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// SoftwareHistory is one entry in the append-only audit log for a (host,
// package) pair.
type SoftwareHistory struct {
	ID          int64     `json:"id"`
	Hostname    string    `json:"hostname"`
	PackageID   string    `json:"package_id"`
	PackageName string    `json:"package_name"`
	OldVersion  string    `json:"old_version"`
	NewVersion  string    `json:"new_version"`
	ChangeType  string    `json:"change_type"`
	DetectedAt  time.Time `json:"detected_at"`
}

// SyncInstalledSoftware diffs the incoming installed-software list against
// the current snapshot for hostname and writes installed/updated/removed
// rows into the audit history. Idempotent — calling with the same payload
// twice produces no new history entries (just refreshes last_seen).
func (d *DB) SyncInstalledSoftware(hostname string, incoming []map[string]any) error {
	type curRow struct{ name, version string }
	current := map[string]curRow{}
	rows, err := d.sql.Query("SELECT package_id, package_name, version FROM installed_software WHERE hostname=?", hostname)
	if err != nil {
		return err
	}
	for rows.Next() {
		var pid string
		var pname, ver sql.NullString
		if err := rows.Scan(&pid, &pname, &ver); err != nil {
			rows.Close()
			return err
		}
		current[pid] = curRow{name: pname.String, version: ver.String}
	}
	rows.Close()

	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsertSQL := "INSERT INTO installed_software (hostname, package_id, package_name, version, source, first_seen, last_seen) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON DUPLICATE KEY UPDATE package_name=VALUES(package_name), version=VALUES(version), source=VALUES(source), last_seen=CURRENT_TIMESTAMP"
	if d.driver == DriverSQLite {
		upsertSQL = "INSERT INTO installed_software (hostname, package_id, package_name, version, source, first_seen, last_seen) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT(hostname,package_id) DO UPDATE SET package_name=excluded.package_name, version=excluded.version, source=excluded.source, last_seen=CURRENT_TIMESTAMP"
	}
	insertHistory, err := tx.Prepare("INSERT INTO installed_software_history (hostname, package_id, package_name, old_version, new_version, change_type) VALUES (?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer insertHistory.Close()
	upsertCurrent, err := tx.Prepare(upsertSQL)
	if err != nil {
		return err
	}
	defer upsertCurrent.Close()

	seen := make(map[string]bool, len(incoming))
	for _, p := range incoming {
		id, _ := p["id"].(string)
		if id == "" {
			continue
		}
		ver, _ := p["version"].(string)
		name, _ := p["name"].(string)
		src, _ := p["source"].(string)
		seen[id] = true

		cur, exists := current[id]
		if !exists {
			if _, err := insertHistory.Exec(hostname, id, name, "", ver, "installed"); err != nil {
				return err
			}
		} else if cur.version != ver {
			if _, err := insertHistory.Exec(hostname, id, name, cur.version, ver, "updated"); err != nil {
				return err
			}
		}
		if _, err := upsertCurrent.Exec(hostname, id, name, ver, src); err != nil {
			return err
		}
	}

	// Find removals: rows in current but not in incoming.
	if len(current) > 0 {
		removeRow, err := tx.Prepare("DELETE FROM installed_software WHERE hostname=? AND package_id=?")
		if err != nil {
			return err
		}
		defer removeRow.Close()
		for id, cur := range current {
			if seen[id] {
				continue
			}
			if _, err := insertHistory.Exec(hostname, id, cur.name, cur.version, "", "removed"); err != nil {
				return err
			}
			if _, err := removeRow.Exec(hostname, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// InstalledSoftwareForHost returns the current snapshot for hostname,
// alphabetically sorted by name.
func (d *DB) InstalledSoftwareForHost(hostname string) ([]InstalledSoftware, error) {
	rows, err := d.sql.Query(
		"SELECT hostname, package_id, package_name, version, source, first_seen, last_seen FROM installed_software WHERE hostname=? ORDER BY LOWER(package_name), package_id",
		hostname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstalledSoftware
	for rows.Next() {
		var s InstalledSoftware
		var pname, ver, src sql.NullString
		if err := rows.Scan(&s.Hostname, &s.PackageID, &pname, &ver, &src, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, err
		}
		s.PackageName = pname.String
		s.Version = ver.String
		s.Source = src.String
		out = append(out, s)
	}
	return out, rows.Err()
}

// SoftwareHistoryForHost returns the history for one (host, package),
// newest first, capped at the given limit (use 200 for the dashboard).
func (d *DB) SoftwareHistoryForHost(hostname, pkgID string, limit int) ([]SoftwareHistory, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.sql.Query(
		"SELECT id, hostname, package_id, package_name, old_version, new_version, change_type, detected_at FROM installed_software_history WHERE hostname=? AND package_id=? ORDER BY detected_at DESC, id DESC LIMIT ?",
		hostname, pkgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SoftwareHistory
	for rows.Next() {
		var h SoftwareHistory
		var pname, ov, nv sql.NullString
		if err := rows.Scan(&h.ID, &h.Hostname, &h.PackageID, &pname, &ov, &nv, &h.ChangeType, &h.DetectedAt); err != nil {
			return nil, err
		}
		h.PackageName = pname.String
		h.OldVersion = ov.String
		h.NewVersion = nv.String
		out = append(out, h)
	}
	return out, rows.Err()
}

// PurgeInstalledForHost wipes both tables for a hostname — called from
// DeletePC so a force-removed device doesn't leave orphan rows.
func (d *DB) PurgeInstalledForHost(hostname string) {
	d.sql.Exec("DELETE FROM installed_software WHERE hostname=?", hostname)
	d.sql.Exec("DELETE FROM installed_software_history WHERE hostname=?", hostname)
}

// -- Users ------------------------------------------------------------------

type User struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"`
	TOTPSecret   *string    `json:"-"`
	TOTPEnabled  bool       `json:"totp_enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at"`
}

func (d *DB) CountUsers() (int, error) {
	var n int
	err := d.sql.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

func (d *DB) CreateUser(username, passwordHash, role string) (int64, error) {
	res, err := d.sql.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
		username, passwordHash, role)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) GetUserByID(id int) (*User, error) {
	row := d.sql.QueryRow(
		"SELECT id, username, password_hash, role, totp_secret, created_at, last_login_at FROM users WHERE id=?", id)
	return scanUser(row)
}

func (d *DB) GetUserByName(username string) (*User, error) {
	row := d.sql.QueryRow(
		"SELECT id, username, password_hash, role, totp_secret, created_at, last_login_at FROM users WHERE username=?", username)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*User, error) {
	var u User
	var totp sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &totp, &u.CreatedAt, &u.LastLoginAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if totp.Valid && totp.String != "" {
		s := totp.String
		u.TOTPSecret = &s
		u.TOTPEnabled = true
	}
	return &u, nil
}

func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.sql.Query(
		"SELECT id, username, password_hash, role, totp_secret, created_at, last_login_at FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var totp sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &totp, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		if totp.Valid && totp.String != "" {
			s := totp.String
			u.TOTPSecret = &s
			u.TOTPEnabled = true
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (d *DB) UpdateUserPassword(id int, passwordHash string) error {
	_, err := d.sql.Exec("UPDATE users SET password_hash=? WHERE id=?", passwordHash, id)
	return err
}

func (d *DB) UpdateUserRole(id int, role string) error {
	_, err := d.sql.Exec("UPDATE users SET role=? WHERE id=?", role, id)
	return err
}

func (d *DB) SetUserTOTPSecret(id int, secret *string) error {
	_, err := d.sql.Exec("UPDATE users SET totp_secret=? WHERE id=?", secret, id)
	return err
}

func (d *DB) DeleteUser(id int) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM sessions WHERE user_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM users WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) TouchUserLogin(id int) error {
	_, err := d.sql.Exec("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?", id)
	return err
}

// -- Sessions ---------------------------------------------------------------

type Session struct {
	ID        string
	UserID    int
	ExpiresAt time.Time
}

func (d *DB) CreateSession(id string, userID int, expires time.Time, ip, ua string) error {
	_, err := d.sql.Exec(
		"INSERT INTO sessions (id, user_id, expires_at, last_seen_at, ip, user_agent) VALUES (?,?,?,CURRENT_TIMESTAMP,?,?)",
		id, userID, expires, nullIfEmpty(ip), nullIfEmpty(ua))
	return err
}

// LookupSession returns the session + associated user if the session is
// present and not expired. A nil User means no valid session.
//
// Implementation note: we do the expiry check in Go instead of SQL so we
// don't have to worry about time-format differences between MariaDB
// (DATETIME) and SQLite (which stores time.Time using whatever the driver
// chose — the lexical comparison against CURRENT_TIMESTAMP is fragile).
func (d *DB) LookupSession(id string) (*Session, *User, error) {
	row := d.sql.QueryRow(
		`SELECT s.id, s.user_id, s.expires_at,
			u.id, u.username, u.password_hash, u.role, u.totp_secret, u.created_at, u.last_login_at
		 FROM sessions s INNER JOIN users u ON u.id=s.user_id
		 WHERE s.id=?`, id)
	var s Session
	var u User
	var totp sql.NullString
	if err := row.Scan(&s.ID, &s.UserID, &s.ExpiresAt,
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &totp, &u.CreatedAt, &u.LastLoginAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		return nil, nil, nil
	}
	if totp.Valid && totp.String != "" {
		x := totp.String
		u.TOTPSecret = &x
		u.TOTPEnabled = true
	}
	// update last_seen_at opportunistically; ignore errors
	d.sql.Exec("UPDATE sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?", id)
	return &s, &u, nil
}

func (d *DB) DeleteSession(id string) error {
	_, err := d.sql.Exec("DELETE FROM sessions WHERE id=?", id)
	return err
}

func (d *DB) PurgeExpiredSessions() error {
	_, err := d.sql.Exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
	return err
}

// -- CVE scanning -----------------------------------------------------------

// CVEEntry is one vulnerability finding. Stored as part of the JSON blob in
// cve_cache.cves_json so the scanner can diff by CVE id cheaply.
type CVEEntry struct {
	ID           string  `json:"id"`
	Severity     string  `json:"severity,omitempty"` // "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "UNKNOWN"
	CVSS         float64 `json:"cvss,omitempty"`
	Summary      string  `json:"summary,omitempty"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	Published    string  `json:"published,omitempty"` // ISO date
	Source       string  `json:"source,omitempty"`    // "osv" / "nvd"
}

// CVECacheEntry is one row of cve_cache, with CVEs already decoded.
type CVECacheEntry struct {
	PackageID string
	Version   string
	Source    string
	CVEs      []CVEEntry
	ScannedAt time.Time
}

// GetCVECache returns the cached CVE list for (pkg_id, version), or nil if
// there is no row. Does not check freshness — caller decides.
func (d *DB) GetCVECache(pkgID, version string) (*CVECacheEntry, error) {
	var (
		src       string
		j         sql.NullString
		scannedAt time.Time
	)
	err := d.sql.QueryRow(
		"SELECT source, cves_json, scanned_at FROM cve_cache WHERE package_id=? AND version=?",
		pkgID, version).Scan(&src, &j, &scannedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e := &CVECacheEntry{
		PackageID: pkgID,
		Version:   version,
		Source:    src,
		ScannedAt: scannedAt,
	}
	if j.Valid && j.String != "" {
		if err := json.Unmarshal([]byte(j.String), &e.CVEs); err != nil {
			return nil, fmt.Errorf("decode cve_cache row: %w", err)
		}
	}
	return e, nil
}

// UpsertCVECache stores the result of a scan for (pkg_id, version). An empty
// cves slice is valid and means "no known CVEs" — we still write the row so
// we don't re-query on every scan cycle.
func (d *DB) UpsertCVECache(pkgID, version, source string, cves []CVEEntry) error {
	raw, err := json.Marshal(cves)
	if err != nil {
		return err
	}
	q := `INSERT INTO cve_cache (package_id, version, source, cves_json, scanned_at)
	      VALUES (?,?,?,?,CURRENT_TIMESTAMP)
	      ON DUPLICATE KEY UPDATE source=VALUES(source), cves_json=VALUES(cves_json), scanned_at=CURRENT_TIMESTAMP`
	if d.driver == DriverSQLite {
		q = `INSERT INTO cve_cache (package_id, version, source, cves_json, scanned_at)
		     VALUES (?,?,?,?,CURRENT_TIMESTAMP)
		     ON CONFLICT(package_id, version) DO UPDATE SET source=excluded.source, cves_json=excluded.cves_json, scanned_at=CURRENT_TIMESTAMP`
	}
	_, err = d.sql.Exec(q, pkgID, version, source, string(raw))
	return err
}

// UniquePackageVersions returns every distinct (package_id, version) pair
// currently seen in installed_software. Rows with blank pkg_id/version are
// skipped — they can't be scanned.
func (d *DB) UniquePackageVersions() ([]struct{ PackageID, Version string }, error) {
	rows, err := d.sql.Query(`SELECT DISTINCT package_id, COALESCE(version,'') FROM installed_software
	                          WHERE package_id<>'' AND version IS NOT NULL AND version<>''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct{ PackageID, Version string }
	for rows.Next() {
		var p, v string
		if err := rows.Scan(&p, &v); err != nil {
			return nil, err
		}
		out = append(out, struct{ PackageID, Version string }{p, v})
	}
	return out, rows.Err()
}

// StaleCVECacheKeys returns (pkg_id, version) pairs that either have no
// cache row or a row older than the given TTL. Used by the scanner to pick
// its work queue.
func (d *DB) StaleCVECacheKeys(ttl time.Duration) ([]struct{ PackageID, Version string }, error) {
	all, err := d.UniquePackageVersions()
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, nil
	}
	// Fetch all fresh keys in one query.
	cutoff := time.Now().Add(-ttl).UTC().Format("2006-01-02 15:04:05")
	rows, err := d.sql.Query("SELECT package_id, version FROM cve_cache WHERE scanned_at >= ?", cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fresh := map[string]bool{}
	for rows.Next() {
		var p, v string
		if err := rows.Scan(&p, &v); err != nil {
			return nil, err
		}
		fresh[p+"\x00"+v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]struct{ PackageID, Version string }, 0, len(all))
	for _, k := range all {
		if !fresh[k.PackageID+"\x00"+k.Version] {
			out = append(out, k)
		}
	}
	return out, nil
}

// CVEHostFinding is a per-host CVE row, joining installed_software × cve_cache
// and enriched with the KEV flag.
type CVEHostFinding struct {
	Hostname    string  `json:"hostname"`
	PackageID   string  `json:"package_id"`
	PackageName string  `json:"package_name"`
	Version     string  `json:"version"`
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Summary     string  `json:"summary"`
	FixedIn     string  `json:"fixed_version,omitempty"`
	Published   string  `json:"published,omitempty"`
	Source      string  `json:"source,omitempty"`
	KEV         bool    `json:"kev"`
}

// CVEFindingsForHost returns every CVE affecting the host's currently-
// installed software. Empty if nothing is vulnerable or the scanner hasn't
// run yet.
func (d *DB) CVEFindingsForHost(hostname string) ([]CVEHostFinding, error) {
	rows, err := d.sql.Query(`
		SELECT s.hostname, s.package_id, COALESCE(s.package_name,''), COALESCE(s.version,''),
		       c.cves_json
		  FROM installed_software s
		  JOIN cve_cache c ON c.package_id=s.package_id AND c.version=s.version
		 WHERE s.hostname=?`, hostname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	kev, err := d.GetKEVSet()
	if err != nil {
		return nil, err
	}
	var out []CVEHostFinding
	for rows.Next() {
		var host, pid, pname, ver string
		var j sql.NullString
		if err := rows.Scan(&host, &pid, &pname, &ver, &j); err != nil {
			return nil, err
		}
		if !j.Valid || j.String == "" {
			continue
		}
		var cves []CVEEntry
		if err := json.Unmarshal([]byte(j.String), &cves); err != nil {
			continue
		}
		for _, c := range cves {
			out = append(out, CVEHostFinding{
				Hostname:    host,
				PackageID:   pid,
				PackageName: pname,
				Version:     ver,
				CVEID:       c.ID,
				Severity:    c.Severity,
				CVSS:        c.CVSS,
				Summary:     c.Summary,
				FixedIn:     c.FixedVersion,
				Published:   c.Published,
				Source:      c.Source,
				KEV:         kev[c.ID],
			})
		}
	}
	return out, rows.Err()
}

// CVESummaryStats is the dashboard top-bar roll-up.
type CVESummaryStats struct {
	OpenCVEs      int            `json:"open_cves"`
	KEVCount      int            `json:"kev_count"`
	AffectedHosts int            `json:"affected_hosts"`
	BySeverity    map[string]int `json:"by_severity"`
	LastScanAt    string         `json:"last_scan_at,omitempty"`
}

// CVESummary computes counters over the join of installed_software × cve_cache.
// Cheap enough to run on every dashboard load for a few-thousand-row inventory.
func (d *DB) CVESummary() (*CVESummaryStats, error) {
	rows, err := d.sql.Query(`
		SELECT s.hostname, c.cves_json
		  FROM installed_software s
		  JOIN cve_cache c ON c.package_id=s.package_id AND c.version=s.version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	kev, err := d.GetKEVSet()
	if err != nil {
		return nil, err
	}
	sum := &CVESummaryStats{BySeverity: map[string]int{}}
	hosts := map[string]bool{}
	for rows.Next() {
		var host string
		var j sql.NullString
		if err := rows.Scan(&host, &j); err != nil {
			return nil, err
		}
		if !j.Valid || j.String == "" {
			continue
		}
		var cves []CVEEntry
		if err := json.Unmarshal([]byte(j.String), &cves); err != nil {
			continue
		}
		for _, c := range cves {
			sum.OpenCVEs++
			if kev[c.ID] {
				sum.KEVCount++
			}
			sev := strings.ToUpper(c.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}
			sum.BySeverity[sev]++
			hosts[host] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sum.AffectedHosts = len(hosts)
	var last sql.NullTime
	_ = d.sql.QueryRow("SELECT MAX(scanned_at) FROM cve_cache").Scan(&last)
	if last.Valid {
		sum.LastScanAt = last.Time.UTC().Format(time.RFC3339)
	}
	return sum, nil
}

// -- CISA KEV --------------------------------------------------------------

// KEVEntry is one CISA KEV catalog row.
type KEVEntry struct {
	CVEID             string
	Vendor            string
	Product           string
	VulnerabilityName string
	DateAdded         string // YYYY-MM-DD
	ShortDescription  string
}

// UpsertKEV replaces the full KEV catalog with the given slice atomically.
// The CISA feed is small (~1200 rows) so a full refresh is fine.
func (d *DB) UpsertKEV(entries []KEVEntry) error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := `INSERT INTO cve_kev (cve_id, vendor, product, vulnerability_name, date_added, short_description, synced_at)
	      VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)
	      ON DUPLICATE KEY UPDATE vendor=VALUES(vendor), product=VALUES(product),
	        vulnerability_name=VALUES(vulnerability_name), date_added=VALUES(date_added),
	        short_description=VALUES(short_description), synced_at=CURRENT_TIMESTAMP`
	if d.driver == DriverSQLite {
		q = `INSERT INTO cve_kev (cve_id, vendor, product, vulnerability_name, date_added, short_description, synced_at)
		     VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)
		     ON CONFLICT(cve_id) DO UPDATE SET vendor=excluded.vendor, product=excluded.product,
		       vulnerability_name=excluded.vulnerability_name, date_added=excluded.date_added,
		       short_description=excluded.short_description, synced_at=CURRENT_TIMESTAMP`
	}
	for _, e := range entries {
		var da any
		if e.DateAdded != "" {
			da = e.DateAdded
		}
		if _, err := tx.Exec(q, e.CVEID, nullIfEmpty(e.Vendor), nullIfEmpty(e.Product),
			nullIfEmpty(e.VulnerabilityName), da, nullIfEmpty(e.ShortDescription)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetKEVSet returns a set of CVE IDs present in the catalog, for cheap
// lookups when building findings.
func (d *DB) GetKEVSet() (map[string]bool, error) {
	rows, err := d.sql.Query("SELECT cve_id FROM cve_kev")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// -- helpers ----------------------------------------------------------------

func nullStr(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
