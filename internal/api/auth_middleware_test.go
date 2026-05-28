package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
	"github.com/Ozark-Security-Labs/Tallow/internal/auth/local"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

type fakeSessionAuthenticator struct {
	principal auth.Principal
	err       error
}

func (f fakeSessionAuthenticator) AuthenticateRequest(*http.Request) (auth.Principal, error) {
	if f.err != nil {
		return auth.Principal{}, f.err
	}
	return f.principal, nil
}

func TestRequireAuthAddsPrincipal(t *testing.T) {
	s := New(config.Default(), slog.Default(), nil)
	s.SessionAuth = fakeSessionAuthenticator{principal: auth.Principal{UserID: "user-1", Roles: []auth.Role{auth.RoleViewer}}}
	handler := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok || principal.UserID != "user-1" {
			t.Fatalf("missing principal: %#v", principal)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/protected", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestRequireAuthRejectsMissingOrInvalidSession(t *testing.T) {
	s := New(config.Default(), slog.Default(), nil)
	handler := s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/protected", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "auth_failed") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	s.SessionAuth = fakeSessionAuthenticator{err: tallowerr.New(tallowerr.CodeAuth, "bad session")}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/protected", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "bad session") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestBearerToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer abc")
	if bearerToken(req) != "abc" {
		t.Fatal("expected bearer token")
	}
	req.Header.Set("Authorization", "Basic abc")
	if bearerToken(req) != "" {
		t.Fatal("unexpected token")
	}
}

func TestProviderHandlersUseManager(t *testing.T) {
	provider := handlerFakePasswordProvider{}
	manager, err := auth.NewManager(provider)
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.Default(), slog.Default(), nil)
	s.Auth = manager

	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/auth/providers", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "local") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/v1/auth/local/login", strings.NewReader(`{"email":"admin@example.com","password":"correct"}`)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "admin@example.com") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

type handlerFakePasswordProvider struct{}

func (handlerFakePasswordProvider) Name() string { return "local" }
func (handlerFakePasswordProvider) LoginMethods(context.Context) ([]auth.LoginMethod, error) {
	return []auth.LoginMethod{{Provider: "local", Type: "password", Label: "Local", Enabled: true}}, nil
}
func (handlerFakePasswordProvider) AuthenticatePassword(_ context.Context, email, password string) (*auth.Identity, error) {
	if email != "admin@example.com" || password != "correct" {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Identity{Provider: "local", ProviderSubject: email, Email: email, Roles: []auth.Role{auth.RoleAdmin}}, nil
}

func TestLocalLoginCreatesAndLogoutRevokesSession(t *testing.T) {
	password := "test-password"
	provider := local.NewProvider(local.Config{Enabled: true, BootstrapAdminEmail: "admin@example.com", BootstrapAdminPassword: password}, nil)
	manager, err := auth.NewManager(provider)
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.Default(), slog.Default(), nil)
	s.Auth = manager
	s.SessionManager = auth.NewSessionManager(auth.NewMemorySessionStore(), auth.SessionOptions{SecureCookies: true})

	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/v1/auth/local/login", strings.NewReader(`{"email":"admin@example.com","password":"`+password+`"}`)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "expires_at") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != auth.DefaultSessionCookieName || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("bad cookies: %#v", cookies)
	}

	logoutReq := httptest.NewRequest("POST", "/v1/auth/logout", nil)
	logoutReq.AddCookie(cookies[0])
	logoutW := httptest.NewRecorder()
	s.Handler.ServeHTTP(logoutW, logoutReq)
	if logoutW.Code != http.StatusNoContent {
		t.Fatalf("%d %s", logoutW.Code, logoutW.Body.String())
	}
	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	protectedReq := httptest.NewRequest("GET", "/protected", nil)
	protectedReq.AddCookie(cookies[0])
	protectedW := httptest.NewRecorder()
	protected.ServeHTTP(protectedW, protectedReq)
	if protectedW.Code != http.StatusUnauthorized {
		t.Fatalf("expected revoked session, got %d", protectedW.Code)
	}
}

func TestProviderHandlerMapsProviderFailures(t *testing.T) {
	manager, err := auth.NewManager(errorProvider{})
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.Default(), slog.Default(), nil)
	s.Auth = manager
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/auth/providers", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "auth_failed") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

type errorProvider struct{}

func (errorProvider) Name() string { return "broken" }
func (errorProvider) LoginMethods(context.Context) ([]auth.LoginMethod, error) {
	return nil, errors.New("boom")
}
