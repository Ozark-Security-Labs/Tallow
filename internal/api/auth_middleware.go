package api

import (
	"net/http"
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

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[len("bearer "):])
}
