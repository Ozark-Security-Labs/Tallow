package github

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
)

type fakeClient struct {
	token string
	user  User
	email string
	teams []Team
	err   error
}

func (f fakeClient) ExchangeCode(context.Context, string, string, string, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}
func (f fakeClient) CurrentUser(context.Context, string) (User, error) {
	if f.err != nil {
		return User{}, f.err
	}
	return f.user, nil
}
func (f fakeClient) PrimaryEmail(context.Context, string) (string, error)    { return f.email, nil }
func (f fakeClient) TeamMemberships(context.Context, string) ([]Team, error) { return f.teams, f.err }

func TestGitHubOAuthStateSignedExpiresAndSingleUse(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	codec := NewStateCodec([]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	raw, state, err := codec.Sign("github", "/findings", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if state.RedirectPath != "/findings" || !strings.Contains(raw, ".") {
		t.Fatalf("bad state: %#v %q", state, raw)
	}
	verified, err := codec.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Nonce != state.Nonce {
		t.Fatalf("wrong state: %#v", verified)
	}
	if _, err := codec.Verify(raw); !errors.Is(err, auth.ErrInvalidOAuthState) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	expiredCodec := NewStateCodec([]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now.Add(2 * time.Minute) })
	if _, err := expiredCodec.Verify(raw); !errors.Is(err, auth.ErrInvalidOAuthState) {
		t.Fatalf("expected expiry rejection, got %v", err)
	}
}

func TestGitHubOAuthCallbackMapsUser(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	provider := NewProvider(Config{Enabled: true, ClientID: "client", ClientSecret: "client-secret-value", CallbackURL: "http://localhost/callback", StateKey: []byte("0123456789abcdef0123456789abcdef"), AllowedTeams: []string{"ozark/sec"}}, fakeClient{token: "token", user: User{ID: 42, Login: "octo", Name: "Octo"}, email: "octo@example.com", teams: []Team{{Org: "ozark", Slug: "sec"}}}, func() time.Time { return now })
	start, err := provider.BeginOAuth(context.Background(), "/triage")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.CompleteOAuth(context.Background(), url.Values{"code": []string{"code"}, "state": []string{start.State}})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != "github" || identity.ProviderSubject != "42" || identity.Username != "octo" || identity.Email != "octo@example.com" || identity.Roles[0] != auth.RoleViewer {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestGitHubOAuthRejectsTamperedStateExchangeFailureAndUnauthorizedTeam(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	provider := NewProvider(Config{Enabled: true, ClientID: "client", ClientSecret: "client-secret-value", CallbackURL: "http://localhost/callback", StateKey: []byte("0123456789abcdef0123456789abcdef"), AllowedOrgs: []string{"allowed"}}, fakeClient{token: "token", user: User{Login: "octo"}, email: "octo@example.com", teams: []Team{{Org: "other", Slug: "team"}}}, func() time.Time { return now })
	if _, err := provider.CompleteOAuth(context.Background(), url.Values{"code": []string{"code"}, "state": []string{"tampered"}}); !errors.Is(err, auth.ErrInvalidOAuthState) {
		t.Fatalf("expected invalid state, got %v", err)
	}
	start, err := provider.BeginOAuth(context.Background(), "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(context.Background(), url.Values{"code": []string{"code"}, "state": []string{start.State}}); !errors.Is(err, auth.ErrIdentityNotAllowed) {
		t.Fatalf("expected identity not allowed, got %v", err)
	}

	failing := NewProvider(Config{Enabled: true, ClientID: "client", ClientSecret: "client-secret-value", CallbackURL: "http://localhost/callback", StateKey: []byte("0123456789abcdef0123456789abcdef")}, fakeClient{err: errors.New("exchange failed")}, func() time.Time { return now })
	start, err = failing.BeginOAuth(context.Background(), "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.CompleteOAuth(context.Background(), url.Values{"code": []string{"code"}, "state": []string{start.State}}); !errors.Is(err, auth.ErrOAuthExchangeFailed) {
		t.Fatalf("expected exchange failure, got %v", err)
	}
}
