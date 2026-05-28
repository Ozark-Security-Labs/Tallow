package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPClient struct {
	BaseURL    string
	OAuthURL   string
	HTTPClient *http.Client
}

func NewHTTPClient() *HTTPClient {
	return &HTTPClient{BaseURL: "https://api.github.com", OAuthURL: "https://github.com/login/oauth/access_token", HTTPClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c *HTTPClient) ExchangeCode(ctx context.Context, code, clientID, clientSecret, callbackURL string) (string, error) {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("client_secret", clientSecret)
	values.Set("code", code)
	values.Set("redirect_uri", callbackURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauthURL(), bytes.NewBufferString(values.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := c.doJSON(req, &body); err != nil {
		return "", err
	}
	if body.AccessToken == "" || body.Error != "" {
		return "", fmt.Errorf("github oauth exchange failed")
	}
	return body.AccessToken, nil
}

func (c *HTTPClient) CurrentUser(ctx context.Context, token string) (User, error) {
	var user User
	req, err := c.apiRequest(ctx, http.MethodGet, "/user", token)
	if err != nil {
		return user, err
	}
	err = c.doJSON(req, &user)
	return user, err
}

func (c *HTTPClient) PrimaryEmail(ctx context.Context, token string) (string, error) {
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	req, err := c.apiRequest(ctx, http.MethodGet, "/user/emails", token)
	if err != nil {
		return "", err
	}
	if err := c.doJSON(req, &emails); err != nil {
		return "", err
	}
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}
	return "", nil
}

func (c *HTTPClient) TeamMemberships(ctx context.Context, token string) ([]Team, error) {
	var teams []struct {
		Slug string `json:"slug"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}
	req, err := c.apiRequest(ctx, http.MethodGet, "/user/teams", token)
	if err != nil {
		return nil, err
	}
	if err := c.doJSON(req, &teams); err != nil {
		return nil, err
	}
	out := make([]Team, 0, len(teams))
	for _, team := range teams {
		out = append(out, Team{Org: team.Org.Login, Slug: team.Slug})
	}
	return out, nil
}

func (c *HTTPClient) apiRequest(ctx context.Context, method, path, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.baseURL(), "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

func (c *HTTPClient) doJSON(req *http.Request, out any) error {
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("github returned status %d", res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (c *HTTPClient) baseURL() string {
	if c != nil && c.BaseURL != "" {
		return c.BaseURL
	}
	return "https://api.github.com"
}

func (c *HTTPClient) oauthURL() string {
	if c != nil && c.OAuthURL != "" {
		return c.OAuthURL
	}
	return "https://github.com/login/oauth/access_token"
}
