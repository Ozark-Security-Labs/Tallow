package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionCookieFlagsAndLookup(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	manager := NewSessionManager(NewMemorySessionStore(), SessionOptions{SecureCookies: true, Now: func() time.Time { return now }})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/local/login", nil)
	_, err := manager.CreateHTTP(w, req, &Identity{Provider: "local", ProviderSubject: "user-1", Email: "admin@example.com", Roles: []Role{RoleAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Name != DefaultSessionCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("bad cookie flags: %#v", cookie)
	}
	if strings.Contains(cookie.Value, "user-1") || len(cookie.Value) < 32 {
		t.Fatalf("session cookie leaks identity or is too short: %q", cookie.Value)
	}
	authReq := httptest.NewRequest("GET", "/v1/auth/me", nil)
	authReq.AddCookie(cookie)
	principal, err := manager.AuthenticateRequest(authReq)
	if err != nil {
		t.Fatal(err)
	}
	if principal.UserID != "user-1" || principal.Roles[0] != RoleAdmin {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	manager := NewSessionManager(NewMemorySessionStore(), SessionOptions{SecureCookies: true, Now: func() time.Time { return now }})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/auth/local/login", nil)
	_, err := manager.CreateHTTP(w, req, &Identity{Provider: "local", ProviderSubject: "user-1", Email: "admin@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]

	logoutReq := httptest.NewRequest("POST", "/v1/auth/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutW := httptest.NewRecorder()
	if err := manager.LogoutHTTP(logoutW, logoutReq); err != nil {
		t.Fatal(err)
	}
	expired := logoutW.Result().Cookies()[0]
	if expired.MaxAge != -1 || !expired.HttpOnly {
		t.Fatalf("logout did not expire cookie: %#v", expired)
	}
	authReq := httptest.NewRequest("GET", "/v1/auth/me", nil)
	authReq.AddCookie(cookie)
	if _, err := manager.AuthenticateRequest(authReq); err == nil {
		t.Fatal("expected revoked session to fail")
	}
}

func TestSessionCookieAllowsDevInsecureMode(t *testing.T) {
	manager := NewSessionManager(NewMemorySessionStore(), SessionOptions{SecureCookies: true, DevInsecureCookies: true})
	w := httptest.NewRecorder()
	_, err := manager.CreateHTTP(w, httptest.NewRequest("POST", "/", nil), &Identity{ProviderSubject: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if w.Result().Cookies()[0].Secure {
		t.Fatal("expected insecure dev cookie")
	}
}
