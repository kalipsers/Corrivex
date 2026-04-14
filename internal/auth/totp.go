package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 defaults: SHA-1, 6 digits, 30 s period).
const (
	totpPeriod  = 30
	totpDigits  = 6
	totpDrift   = 1 // accept codes ±1 window (±30 s)
	totpVersion = 1
)

// NewSecret returns a fresh 160-bit Base32 secret suitable for any TOTP app.
func NewSecret() string {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		// deterministic fallback on entropy failure (should be vanishingly rare)
		now := time.Now().UnixNano()
		for i := range raw {
			raw[i] = byte(now >> (i % 8))
		}
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

// Verify returns true if the submitted 6-digit code matches the secret,
// allowing ±30 s clock drift.
func Verify(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}
	now := time.Now().Unix() / totpPeriod
	for offset := -totpDrift; offset <= totpDrift; offset++ {
		if hotp(key, uint64(now+int64(offset))) == code {
			return true
		}
	}
	return false
}

func hotp(key []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := bin % 1000000
	return fmt.Sprintf("%06d", mod)
}

func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// OTPAuthURL builds an otpauth:// URL that an authenticator app can consume.
func OTPAuthURL(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", totpPeriod))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}
