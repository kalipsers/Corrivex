package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// SessionCookieName is the cookie that carries the session ID.
const SessionCookieName = "cv_session"

// NewSessionID returns a 64-character hex token (256 bits of CSPRNG).
func NewSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CookieSecure reports whether the current request should set a Secure cookie.
func CookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

// Roles -- higher number = more privileges.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// HasRole reports whether the user's role grants at least the required role.
func HasRole(userRole, required string) bool {
	return rank(userRole) >= rank(required)
}

func rank(role string) int {
	switch role {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// CtxUser is the context key used to stash the current user on a request.
type ctxKey struct{}

var CtxUser = ctxKey{}

// WithUser returns a copy of ctx with user attached under CtxUser.
func WithUser(ctx context.Context, u any) context.Context {
	return context.WithValue(ctx, CtxUser, u)
}
