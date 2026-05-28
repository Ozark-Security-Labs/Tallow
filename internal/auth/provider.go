package auth

import (
	"context"
	"net/url"
	"sort"
	"strings"
)

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

type Identity struct {
	Provider        string
	ProviderSubject string
	Email           string
	Username        string
	DisplayName     string
	Roles           []Role
}

type LoginMethod struct {
	Provider string `json:"provider"`
	Type     string `json:"type"`
	Label    string `json:"label"`
	LoginURL string `json:"login_url,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type OAuthStart struct {
	Provider    string
	RedirectURL string
	State       string
	ExpiresAt   int64
}

type Provider interface {
	Name() string
	LoginMethods(ctx context.Context) ([]LoginMethod, error)
}

type PasswordProvider interface {
	Provider
	AuthenticatePassword(ctx context.Context, email, password string) (*Identity, error)
}

type OAuthProvider interface {
	Provider
	BeginOAuth(ctx context.Context, redirectPath string) (*OAuthStart, error)
	CompleteOAuth(ctx context.Context, query url.Values) (*Identity, error)
}

type Manager struct {
	providers map[string]Provider
}

func NewManager(providers ...Provider) (*Manager, error) {
	m := &Manager{providers: map[string]Provider{}}
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		name := strings.TrimSpace(provider.Name())
		if name == "" {
			return nil, ErrProviderMisconfigured
		}
		if _, ok := m.providers[name]; ok {
			return nil, ErrProviderMisconfigured
		}
		m.providers[name] = provider
	}
	return m, nil
}

func (m *Manager) LoginMethods(ctx context.Context) ([]LoginMethod, error) {
	if m == nil {
		return []LoginMethod{}, nil
	}
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	methods := []LoginMethod{}
	for _, name := range names {
		providerMethods, err := m.providers[name].LoginMethods(ctx)
		if err != nil {
			return nil, WrapProviderError(err)
		}
		methods = append(methods, providerMethods...)
	}
	return methods, nil
}

func (m *Manager) AuthenticatePassword(ctx context.Context, providerName, email, password string) (*Identity, error) {
	provider, ok := m.provider(providerName)
	if !ok {
		return nil, ErrProviderDisabled
	}
	passwordProvider, ok := provider.(PasswordProvider)
	if !ok {
		return nil, ErrProviderDisabled
	}
	identity, err := passwordProvider.AuthenticatePassword(ctx, email, password)
	if err != nil {
		return nil, WrapProviderError(err)
	}
	return identity, nil
}

func (m *Manager) BeginOAuth(ctx context.Context, providerName, redirectPath string) (*OAuthStart, error) {
	provider, ok := m.provider(providerName)
	if !ok {
		return nil, ErrProviderDisabled
	}
	oauthProvider, ok := provider.(OAuthProvider)
	if !ok {
		return nil, ErrProviderDisabled
	}
	start, err := oauthProvider.BeginOAuth(ctx, redirectPath)
	if err != nil {
		return nil, WrapProviderError(err)
	}
	return start, nil
}

func (m *Manager) CompleteOAuth(ctx context.Context, providerName string, query url.Values) (*Identity, error) {
	provider, ok := m.provider(providerName)
	if !ok {
		return nil, ErrProviderDisabled
	}
	oauthProvider, ok := provider.(OAuthProvider)
	if !ok {
		return nil, ErrProviderDisabled
	}
	identity, err := oauthProvider.CompleteOAuth(ctx, query)
	if err != nil {
		return nil, WrapProviderError(err)
	}
	return identity, nil
}

func (m *Manager) provider(name string) (Provider, bool) {
	if m == nil || strings.TrimSpace(name) == "" {
		return nil, false
	}
	provider, ok := m.providers[name]
	return provider, ok
}
