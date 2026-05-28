package api

import (
	"encoding/json"
	"net/http"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
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
	writeJSON(w, http.StatusOK, identityResponse{Identity: identity})
}
