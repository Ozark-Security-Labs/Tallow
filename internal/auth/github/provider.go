package github

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
)

type Config struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	CallbackURL  string
	AllowedOrgs  []string
	AllowedTeams []string
	StateKey     []byte
	StateTTL     time.Duration
}

type Client interface {
	ExchangeCode(ctx context.Context, code, clientID, clientSecret, callbackURL string) (string, error)
	CurrentUser(ctx context.Context, accessToken string) (User, error)
	PrimaryEmail(ctx context.Context, accessToken string) (string, error)
	TeamMemberships(ctx context.Context, accessToken string) ([]Team, error)
}

type User struct {
	ID        int64
	Login     string
	Name      string
	Email     string
	AvatarURL string
}

type Team struct {
	Org  string
	Slug string
}

type Provider struct {
	config Config
	client Client
	state  *StateCodec
}

func NewProvider(config Config, client Client, now func() time.Time) *Provider {
	if config.StateTTL <= 0 {
		config.StateTTL = 10 * time.Minute
	}
	return &Provider{config: config, client: client, state: NewStateCodec(config.StateKey, now)}
}

func (p *Provider) Name() string { return "github" }

func (p *Provider) LoginMethods(context.Context) ([]auth.LoginMethod, error) {
	if p == nil || !p.config.Enabled {
		return []auth.LoginMethod{}, nil
	}
	return []auth.LoginMethod{{Provider: "github", Type: "oauth", Label: "GitHub", LoginURL: "/v1/auth/github/login", Enabled: true}}, nil
}

func (p *Provider) BeginOAuth(_ context.Context, redirectPath string) (*auth.OAuthStart, error) {
	if p == nil || !p.config.Enabled || p.config.ClientID == "" {
		return nil, auth.ErrProviderDisabled
	}
	rawState, state, err := p.state.Sign("github", redirectPath, p.config.StateTTL)
	if err != nil {
		return nil, auth.ErrInvalidOAuthState
	}
	values := url.Values{}
	values.Set("client_id", p.config.ClientID)
	values.Set("redirect_uri", p.config.CallbackURL)
	values.Set("scope", "read:user user:email read:org")
	values.Set("state", rawState)
	return &auth.OAuthStart{Provider: "github", RedirectURL: "https://github.com/login/oauth/authorize?" + values.Encode(), State: rawState, ExpiresAt: state.ExpiresAtUnix}, nil
}

func (p *Provider) CompleteOAuth(ctx context.Context, query url.Values) (*auth.Identity, error) {
	if p == nil || !p.config.Enabled || p.client == nil {
		return nil, auth.ErrProviderDisabled
	}
	state, err := p.state.Verify(query.Get("state"))
	if err != nil || state.Provider != "github" {
		return nil, auth.ErrInvalidOAuthState
	}
	code := strings.TrimSpace(query.Get("code"))
	if code == "" {
		return nil, auth.ErrOAuthExchangeFailed
	}
	token, err := p.client.ExchangeCode(ctx, code, p.config.ClientID, p.config.ClientSecret, p.config.CallbackURL)
	if err != nil || token == "" {
		return nil, auth.ErrOAuthExchangeFailed
	}
	user, err := p.client.CurrentUser(ctx, token)
	if err != nil {
		return nil, auth.ErrOAuthExchangeFailed
	}
	email := strings.TrimSpace(user.Email)
	if email == "" {
		email, _ = p.client.PrimaryEmail(ctx, token)
	}
	if email == "" {
		return nil, auth.ErrIdentityNotAllowed
	}
	teams, err := p.client.TeamMemberships(ctx, token)
	if err != nil {
		return nil, auth.ErrIdentityNotAllowed
	}
	if !allowedByHooks(p.config.AllowedOrgs, p.config.AllowedTeams, teams) {
		return nil, auth.ErrIdentityNotAllowed
	}
	return &auth.Identity{Provider: "github", ProviderSubject: strings.TrimSpace(user.Login), Email: email, Username: user.Login, DisplayName: user.Name, Roles: []auth.Role{auth.RoleViewer}}, nil
}

func allowedByHooks(orgs, teams []string, memberships []Team) bool {
	if len(orgs) == 0 && len(teams) == 0 {
		return true
	}
	allowedOrgs := canonicalSet(orgs)
	allowedTeams := canonicalSet(teams)
	for _, membership := range memberships {
		org := strings.ToLower(strings.TrimSpace(membership.Org))
		team := org + "/" + strings.ToLower(strings.TrimSpace(membership.Slug))
		if _, ok := allowedOrgs[org]; ok {
			return true
		}
		if _, ok := allowedTeams[team]; ok {
			return true
		}
	}
	return false
}

func canonicalSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	for _, value := range sorted {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}
