package local

import (
	"context"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
)

type Config struct {
	Enabled                bool
	BootstrapAdminEmail    string
	BootstrapAdminPassword string
}

type UserRecord struct {
	ID           string
	Email        string
	DisplayName  string
	PasswordHash string
	Roles        []auth.Role
	Status       string
}

type UserStore interface {
	AdminExists(context.Context) (bool, error)
	FindByEmail(context.Context, string) (UserRecord, error)
}

type Provider struct {
	config Config
	store  UserStore
}

func NewProvider(config Config, store UserStore) *Provider {
	return &Provider{config: config, store: store}
}

func (p *Provider) Name() string { return "local" }

func (p *Provider) LoginMethods(context.Context) ([]auth.LoginMethod, error) {
	if p == nil || !p.config.Enabled {
		return []auth.LoginMethod{}, nil
	}
	return []auth.LoginMethod{{Provider: "local", Type: "password", Label: "Email and password", Enabled: true}}, nil
}

func (p *Provider) AuthenticatePassword(ctx context.Context, email, password string) (*auth.Identity, error) {
	if p == nil || !p.config.Enabled {
		return nil, auth.ErrProviderDisabled
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return nil, auth.ErrInvalidCredentials
	}
	if p.bootstrapAllowed(ctx, email, password) {
		return &auth.Identity{Provider: "local", ProviderSubject: email, Email: email, DisplayName: "Bootstrap Admin", Roles: []auth.Role{auth.RoleAdmin}}, nil
	}
	if p.store == nil {
		return nil, auth.ErrInvalidCredentials
	}
	user, err := p.store.FindByEmail(ctx, email)
	if err != nil || user.Status == "disabled" || !VerifyPassword(user.PasswordHash, password) {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Identity{Provider: "local", ProviderSubject: user.ID, Email: user.Email, DisplayName: user.DisplayName, Roles: append([]auth.Role(nil), user.Roles...)}, nil
}

func (p *Provider) bootstrapAllowed(ctx context.Context, email, password string) bool {
	if p.config.BootstrapAdminEmail == "" || p.config.BootstrapAdminPassword == "" {
		return false
	}
	if !strings.EqualFold(email, p.config.BootstrapAdminEmail) || password != p.config.BootstrapAdminPassword {
		return false
	}
	if p.store == nil {
		return true
	}
	exists, err := p.store.AdminExists(ctx)
	return err == nil && !exists
}
