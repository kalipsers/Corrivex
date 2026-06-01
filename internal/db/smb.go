package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// -- SMB credentials (1.7.2) ----------------------------------------------

// SMBCredential describes one authenticated SMB share the agent can
// use to access installer files. Passwords are stored encrypted
// (AES-GCM) using the server-local encryption key.
type SMBCredential struct {
	ID        int64     `json:"id"`
	ShareRoot string    `json:"share_root"`
	Username  string    `json:"username"`
	Domain    string    `json:"domain"`
	Notes     string    `json:"notes,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// Password is set only when decrypting for an agent call; never
	// populated by ListSMBCredentials (the admin API returns rows
	// without it — write-only field).
	Password string `json:"password,omitempty"`
}

// ListSMBCredentials returns every row, password omitted. Sorted by
// share_root length desc so longest-prefix-match lookups are cheap.
func (d *DB) ListSMBCredentials() ([]SMBCredential, error) {
	rows, err := d.sql.Query(
		"SELECT id, share_root, username, COALESCE(domain,''), COALESCE(notes,''), COALESCE(created_by,''), created_at FROM smb_credentials ORDER BY LENGTH(share_root) DESC, share_root")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SMBCredential
	for rows.Next() {
		var c SMBCredential
		if err := rows.Scan(&c.ID, &c.ShareRoot, &c.Username, &c.Domain, &c.Notes, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpsertSMBCredential stores a credential encrypting the given password.
// Returns the row id. Upserts by share_root.
func (d *DB) UpsertSMBCredential(c SMBCredential, password string) (int64, error) {
	if strings.TrimSpace(c.ShareRoot) == "" || strings.TrimSpace(c.Username) == "" {
		return 0, errors.New("share_root and username are required")
	}
	key, err := d.smbKey()
	if err != nil {
		return 0, err
	}
	// When editing an existing row the admin may pass the sentinel
	// "__keep__" in place of the password — leave ciphertext alone.
	encB64 := ""
	if password != "" && password != "__keep__" {
		ct, err := encryptGCM(key, []byte(password))
		if err != nil {
			return 0, err
		}
		encB64 = base64.StdEncoding.EncodeToString(ct)
	}

	var existing int64
	err = d.sql.QueryRow("SELECT id FROM smb_credentials WHERE share_root=?", c.ShareRoot).Scan(&existing)
	if err == sql.ErrNoRows {
		if encB64 == "" {
			return 0, errors.New("password is required when adding a new credential")
		}
		res, err := d.sql.Exec(
			"INSERT INTO smb_credentials (share_root, username, domain, password_enc, notes, created_by) VALUES (?,?,?,?,?,?)",
			c.ShareRoot, c.Username, nullIfEmpty(c.Domain), encB64, nullIfEmpty(c.Notes), nullIfEmpty(c.CreatedBy))
		if err != nil {
			return 0, err
		}
		id, _ := res.LastInsertId()
		return id, nil
	}
	if err != nil {
		return 0, err
	}
	// Build update statement based on whether the password is changing.
	if encB64 != "" {
		_, err = d.sql.Exec(
			"UPDATE smb_credentials SET username=?, domain=?, password_enc=?, notes=? WHERE id=?",
			c.Username, nullIfEmpty(c.Domain), encB64, nullIfEmpty(c.Notes), existing)
	} else {
		_, err = d.sql.Exec(
			"UPDATE smb_credentials SET username=?, domain=?, notes=? WHERE id=?",
			c.Username, nullIfEmpty(c.Domain), nullIfEmpty(c.Notes), existing)
	}
	return existing, err
}

// DeleteSMBCredential removes one row by id.
func (d *DB) DeleteSMBCredential(id int64) error {
	_, err := d.sql.Exec("DELETE FROM smb_credentials WHERE id=?", id)
	return err
}

// LookupSMBCredential returns the decrypted credential whose share_root
// is the longest prefix of `path`, or nil if none match. The returned
// SMBCredential's Password is populated.
func (d *DB) LookupSMBCredential(path string) (*SMBCredential, error) {
	rows, err := d.sql.Query(
		"SELECT id, share_root, username, COALESCE(domain,''), password_enc, COALESCE(notes,''), COALESCE(created_by,''), created_at FROM smb_credentials ORDER BY LENGTH(share_root) DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	key, kerr := d.smbKey()
	if kerr != nil {
		return nil, kerr
	}
	lowPath := strings.ToLower(strings.TrimSpace(path))
	for rows.Next() {
		var c SMBCredential
		var enc string
		if err := rows.Scan(&c.ID, &c.ShareRoot, &c.Username, &c.Domain, &enc, &c.Notes, &c.CreatedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		if !uncPathHasRoot(lowPath, strings.ToLower(c.ShareRoot)) {
			continue
		}
		ct, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, fmt.Errorf("decode smb ciphertext: %w", err)
		}
		pt, err := decryptGCM(key, ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt smb password: %w", err)
		}
		c.Password = string(pt)
		return &c, nil
	}
	return nil, rows.Err()
}

func uncPathHasRoot(path, root string) bool {
	path = strings.TrimRight(path, `\/`)
	root = strings.TrimRight(root, `\/`)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+`\`) || strings.HasPrefix(path, root+`/`)
}

// -- encryption helpers ----------------------------------------------------

var (
	smbKeyCacheMu sync.Mutex
	smbKeyCache   []byte
)

// smbKey returns the 32-byte AES-256 key used for SMB password at-rest
// encryption. Source precedence:
//  1. CORRIVEX_SMB_KEY env var (hex, 64 chars). Fails fast if malformed.
//  2. `smb_key` row in the settings table (generated on first boot).
func (d *DB) smbKey() ([]byte, error) {
	smbKeyCacheMu.Lock()
	defer smbKeyCacheMu.Unlock()
	if smbKeyCache != nil {
		return smbKeyCache, nil
	}
	if hex := strings.TrimSpace(os.Getenv("CORRIVEX_SMB_KEY")); hex != "" {
		k, err := decodeHexKey(hex)
		if err != nil {
			return nil, fmt.Errorf("CORRIVEX_SMB_KEY: %w", err)
		}
		smbKeyCache = k
		return k, nil
	}
	stored := d.Setting("smb_key", "")
	if stored != "" {
		k, err := base64.StdEncoding.DecodeString(stored)
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("smb_key setting is corrupt; delete the row to regenerate")
		}
		smbKeyCache = k
		return k, nil
	}
	// Generate + persist a fresh key.
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := d.SetSetting("smb_key", base64.StdEncoding.EncodeToString(k)); err != nil {
		return nil, err
	}
	smbKeyCache = k
	return k, nil
}

func decodeHexKey(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, errors.New("must be 64 hex characters (32 bytes)")
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		a, err := hexNibble(s[i*2])
		if err != nil {
			return nil, err
		}
		b, err := hexNibble(s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = a<<4 | b
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex char %q", c)
}

// encryptGCM returns nonce||ciphertext. Nonce is 12 bytes.
func encryptGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptGCM inverts encryptGCM. Expects nonce||ciphertext.
func decryptGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}
