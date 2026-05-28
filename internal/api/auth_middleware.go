package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
	"github.com/Ozark-Security-Labs/Tallow/internal/rbac"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

type SessionAuthenticator interface {
	AuthenticateRequest(*http.Request) (auth.Principal, error)
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticator := s.SessionAuth
		if authenticator == nil && s.SessionManager != nil {
			authenticator = s.SessionManager
		}
		if authenticator == nil {
			writeError(w, r, tallowerr.New(tallowerr.CodeAuth, "authentication required"))
			return
		}
		principal, err := authenticator.AuthenticateRequest(r)
		if err != nil {
			writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.ContextWithPrincipal(r.Context(), principal)))
	})
}

func requirePermission(permission rbac.Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok || !rbac.Allowed(principal.Roles, permission) {
			writeError(w, r, tallowerr.New(tallowerr.CodePermissionDenied, "permission denied"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" && !sameOrigin(origin, r.Host) {
			writeError(w, r, tallowerr.New(tallowerr.CodePermissionDenied, "origin not allowed"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	parsed, err := url.Parse(origin)
	return err == nil && strings.EqualFold(parsed.Host, host)
}

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[len("bearer "):])
}
