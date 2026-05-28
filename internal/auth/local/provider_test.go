package local

import (
	"context"
	"errors"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
)

type fakeUserStore struct {
	adminExists bool
	user        UserRecord
}

func (f fakeUserStore) AdminExists(context.Context) (bool, error) { return f.adminExists, nil }
func (f fakeUserStore) FindByEmail(_ context.Context, email string) (UserRecord, error) {
	if f.user.Email == email {
		return f.user, nil
	}
	return UserRecord{}, errors.New("not found")
}

func TestBootstrapAdminUntilPersistedAdminExists(t *testing.T) {
	password := "test-password"
	provider := NewProvider(Config{Enabled: true, BootstrapAdminEmail: "Admin@Example.com", BootstrapAdminPassword: password}, fakeUserStore{})
	identity, err := provider.AuthenticatePassword(context.Background(), "admin@example.com", password)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Roles[0] != auth.RoleAdmin {
		t.Fatalf("expected admin, got %#v", identity.Roles)
	}

	provider = NewProvider(Config{Enabled: true, BootstrapAdminEmail: "admin@example.com", BootstrapAdminPassword: password}, fakeUserStore{adminExists: true})
	if _, err := provider.AuthenticatePassword(context.Background(), "admin@example.com", password); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected bootstrap to stop after persisted admin, got %v", err)
	}
}

func TestPasswordHashVerify(t *testing.T) {
	password := "test-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if hash == password || !VerifyPassword(hash, password) {
		t.Fatalf("hash did not verify: %q", hash)
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password verified")
	}
	if VerifyPassword("plaintext", "plaintext") {
		t.Fatal("plaintext should not verify")
	}
}

func TestPersistedLocalUser(t *testing.T) {
	password := "test-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewProvider(Config{Enabled: true}, fakeUserStore{user: UserRecord{ID: "user-1", Email: "admin@example.com", DisplayName: "Admin", PasswordHash: hash, Roles: []auth.Role{auth.RoleAdmin}, Status: "active"}})
	identity, err := provider.AuthenticatePassword(context.Background(), "admin@example.com", password)
	if err != nil {
		t.Fatal(err)
	}
	if identity.ProviderSubject != "user-1" || identity.DisplayName != "Admin" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if _, err := provider.AuthenticatePassword(context.Background(), "admin@example.com", "wrong"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestDisabledProvider(t *testing.T) {
	provider := NewProvider(Config{}, nil)
	methods, err := provider.LoginMethods(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 0 {
		t.Fatalf("expected no methods: %#v", methods)
	}
	if _, err := provider.AuthenticatePassword(context.Background(), "a", "b"); !errors.Is(err, auth.ErrProviderDisabled) {
		t.Fatalf("expected disabled provider, got %v", err)
	}
}
