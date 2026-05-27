package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
)

type Client struct {
	BaseURL  string
	Token    string
	HTTP     *http.Client
	MaxBytes int64
}

func NewClient(token string) *Client {
	return &Client{BaseURL: "https://api.github.com", Token: token, HTTP: http.DefaultClient, MaxBytes: 1 << 20}
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	base := strings.TrimRight(c.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, "GET", base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 401:
		return scm.ErrUnauthorized
	case 403:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return scm.ErrRateLimited
		}
		return scm.ErrForbidden
	case 404:
		return scm.ErrNotFound
	default:
		return fmt.Errorf("%w: status %d", scm.ErrInvalidResponse, resp.StatusCode)
	}
	limit := c.MaxBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	return json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(v)
}
