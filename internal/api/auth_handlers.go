package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
	"github.com/Ozark-Security-Labs/Tallow/internal/rbac"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"github.com/go-chi/chi/v5"
)

type authProvidersResponse struct {
	Items []auth.LoginMethod `json:"items"`
}

type localLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type identityResponse struct {
	Identity *auth.Identity `json:"identity"`
}

type sessionResponse struct {
	User      *auth.Identity `json:"user"`
	ExpiresAt string         `json:"expires_at"`
}

type currentUserResponse struct {
	User         auth.Principal `json:"user"`
	Capabilities []string       `json:"capabilities"`
}

type usersResponse struct {
	Items []auth.Principal `json:"items"`
}

func (s *Server) listAuthProviders(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, http.StatusOK, authProvidersResponse{Items: []auth.LoginMethod{}})
		return
	}
	methods, err := s.Auth.LoginMethods(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	if methods == nil {
		methods = []auth.LoginMethod{}
	}
	writeJSON(w, http.StatusOK, authProvidersResponse{Items: methods})
}

func (s *Server) localLogin(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeError(w, r, auth.ErrProviderDisabled)
		return
	}
	var req localLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, tallowerr.New(tallowerr.CodeValidation, "invalid login request"))
		return
	}
	identity, err := s.Auth.AuthenticatePassword(r.Context(), "local", req.Email, req.Password)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if s.SessionManager == nil {
		writeJSON(w, http.StatusOK, identityResponse{Identity: identity})
		return
	}
	session, err := s.SessionManager.CreateHTTP(w, r, identity)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{User: identity, ExpiresAt: session.ExpiresAt.Format(time.RFC3339)})
}

func (s *Server) githubLogin(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeError(w, r, auth.ErrProviderDisabled)
		return
	}
	start, err := s.Auth.BeginOAuth(r.Context(), "github", r.URL.Query().Get("redirect_path"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	http.Redirect(w, r, start.RedirectURL, http.StatusFound)
}

func (s *Server) githubCallback(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeError(w, r, auth.ErrProviderDisabled)
		return
	}
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		provider = "github"
	}
	identity, err := s.Auth.CompleteOAuth(r.Context(), provider, r.URL.Query())
	if err != nil {
		writeError(w, r, err)
		return
	}
	if s.SessionManager != nil {
		if _, err := s.SessionManager.CreateHTTP(w, r, identity); err != nil {
			writeError(w, r, err)
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, tallowerr.New(tallowerr.CodeAuth, "authentication required"))
		return
	}
	permissions := rbac.Capabilities(principal.Roles)
	capabilities := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		capabilities = append(capabilities, string(permission))
	}
	writeJSON(w, http.StatusOK, currentUserResponse{User: principal, Capabilities: capabilities})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, usersResponse{Items: []auth.Principal{}})
}

func (s *Server) updateUserRoles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "roles_updated"})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.SessionManager != nil {
		if err := s.SessionManager.LogoutHTTP(w, r); err != nil {
			writeError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
