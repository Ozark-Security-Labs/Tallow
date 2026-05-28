package auth

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

type fakePasswordProvider struct {
	name string
	err  error
}

func (f fakePasswordProvider) Name() string { return f.name }
func (f fakePasswordProvider) LoginMethods(context.Context) ([]LoginMethod, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []LoginMethod{{Provider: f.name, Type: "password", Label: "Local", Enabled: true}}, nil
}
func (f fakePasswordProvider) AuthenticatePassword(_ context.Context, email, password string) (*Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	if email != "admin@example.com" || password != "correct" {
		return nil, ErrInvalidCredentials
	}
	return &Identity{Provider: f.name, ProviderSubject: email, Email: email, Roles: []Role{RoleAdmin}}, nil
}

func TestManagerLoginMethodsDeterministic(t *testing.T) {
	m, err := NewManager(fakePasswordProvider{name: "z"}, fakePasswordProvider{name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	methods, err := m.LoginMethods(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{methods[0].Provider, methods[1].Provider}; got[0] != "a" || got[1] != "z" {
		t.Fatalf("methods not sorted: %#v", got)
	}
}

func TestManagerAuthenticatePassword(t *testing.T) {
	m, err := NewManager(fakePasswordProvider{name: "local"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := m.AuthenticatePassword(context.Background(), "local", "admin@example.com", "correct")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Email != "admin@example.com" || identity.Roles[0] != RoleAdmin {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	_, err = m.AuthenticatePassword(context.Background(), "local", "admin@example.com", "wrong")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	_, err = m.AuthenticatePassword(context.Background(), "missing", "admin@example.com", "correct")
	if !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("expected disabled provider, got %v", err)
	}
}

func TestOAuthProviderInterface(t *testing.T) {
	var _ OAuthProvider = fakeOAuthProvider{}
	m, err := NewManager(fakeOAuthProvider{})
	if err != nil {
		t.Fatal(err)
	}
	start, err := m.BeginOAuth(context.Background(), "github", "/findings")
	if err != nil {
		t.Fatal(err)
	}
	if start.Provider != "github" || start.RedirectURL == "" {
		t.Fatalf("unexpected start: %#v", start)
	}
	identity, err := m.CompleteOAuth(context.Background(), "github", url.Values{"code": []string{"ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != "github" || identity.Email == "" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

type fakeOAuthProvider struct{}

func (fakeOAuthProvider) Name() string { return "github" }
func (fakeOAuthProvider) LoginMethods(context.Context) ([]LoginMethod, error) {
	return []LoginMethod{{Provider: "github", Type: "oauth", Label: "GitHub", LoginURL: "/v1/auth/github/login", Enabled: true}}, nil
}
func (fakeOAuthProvider) BeginOAuth(context.Context, string) (*OAuthStart, error) {
	return &OAuthStart{Provider: "github", RedirectURL: "https://github.com/login/oauth/authorize", State: "state"}, nil
}
func (fakeOAuthProvider) CompleteOAuth(context.Context, url.Values) (*Identity, error) {
	return &Identity{Provider: "github", ProviderSubject: "42", Email: "octo@example.com", Username: "octo"}, nil
}
