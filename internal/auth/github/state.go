package github

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
)

type OAuthState struct {
	Provider      string `json:"provider"`
	Nonce         string `json:"nonce"`
	IssuedAtUnix  int64  `json:"issued_at"`
	ExpiresAtUnix int64  `json:"expires_at"`
	RedirectPath  string `json:"redirect_path"`
}

type StateCodec struct {
	key      []byte
	now      func() time.Time
	consumed map[string]struct{}
	mu       sync.Mutex
}

func NewStateCodec(key []byte, now func() time.Time) *StateCodec {
	if now == nil {
		now = time.Now
	}
	return &StateCodec{key: append([]byte(nil), key...), now: now, consumed: map[string]struct{}{}}
}

func (c *StateCodec) Sign(provider, redirectPath string, ttl time.Duration) (string, OAuthState, error) {
	if len(c.key) < 16 {
		return "", OAuthState{}, errors.New("oauth state signing key must be at least 16 bytes")
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", OAuthState{}, err
	}
	now := c.now().UTC()
	state := OAuthState{Provider: provider, Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes), IssuedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(ttl).Unix(), RedirectPath: safeRedirectPath(redirectPath)}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", OAuthState{}, err
	}
	sig := sign(c.key, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), state, nil
}

func (c *StateCodec) Verify(raw string) (OAuthState, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || len(c.key) < 16 {
		return OAuthState{}, auth.ErrInvalidOAuthState
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return OAuthState{}, auth.ErrInvalidOAuthState
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(sig, sign(c.key, payload)) {
		return OAuthState{}, auth.ErrInvalidOAuthState
	}
	var state OAuthState
	if err := json.Unmarshal(payload, &state); err != nil {
		return OAuthState{}, auth.ErrInvalidOAuthState
	}
	if c.now().UTC().Unix() > state.ExpiresAtUnix {
		return OAuthState{}, auth.ErrInvalidOAuthState
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.consumed[state.Nonce]; ok {
		return OAuthState{}, auth.ErrInvalidOAuthState
	}
	c.consumed[state.Nonce] = struct{}{}
	return state, nil
}

func sign(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func safeRedirectPath(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "/"
	}
	return raw
}
