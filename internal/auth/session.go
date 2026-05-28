package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

const DefaultSessionCookieName = "tallow_session"

type Session struct {
	ID         string
	TokenHash  string
	UserID     string
	Email      string
	Provider   string
	Roles      []Role
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
	LastSeenAt time.Time
}

type SessionStore interface {
	CreateSession(context.Context, Session) (Session, error)
	GetSessionByTokenHash(context.Context, string, time.Time) (Session, error)
	RevokeSession(context.Context, string, time.Time) error
}

type SessionOptions struct {
	CookieName         string
	TTL                time.Duration
	SecureCookies      bool
	DevInsecureCookies bool
	Now                func() time.Time
}

type SessionManager struct {
	store   SessionStore
	options SessionOptions
}

func NewSessionManager(store SessionStore, options SessionOptions) *SessionManager {
	if options.CookieName == "" {
		options.CookieName = DefaultSessionCookieName
	}
	if options.TTL <= 0 {
		options.TTL = 24 * time.Hour
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SessionManager{store: store, options: options}
}

func (m *SessionManager) CreateHTTP(w http.ResponseWriter, r *http.Request, identity *Identity) (Session, error) {
	if m == nil || m.store == nil {
		return Session{}, tallowerr.New(tallowerr.CodeAuth, "session manager unavailable")
	}
	if identity == nil {
		return Session{}, tallowerr.New(tallowerr.CodeAuth, "identity required")
	}
	token, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	now := m.options.Now().UTC()
	session := Session{
		TokenHash: hashToken(token),
		UserID:    identity.ProviderSubject,
		Email:     identity.Email,
		Provider:  identity.Provider,
		Roles:     append([]Role(nil), identity.Roles...),
		CreatedAt: now,
		ExpiresAt: now.Add(m.options.TTL),
	}
	created, err := m.store.CreateSession(r.Context(), session)
	if err != nil {
		return Session{}, err
	}
	http.SetCookie(w, m.cookie(token, created.ExpiresAt, 0))
	return created, nil
}

func (m *SessionManager) AuthenticateRequest(r *http.Request) (Principal, error) {
	if m == nil || m.store == nil {
		return Principal{}, tallowerr.New(tallowerr.CodeAuth, "authentication required")
	}
	cookie, err := r.Cookie(m.options.CookieName)
	if err != nil || cookie.Value == "" {
		return Principal{}, tallowerr.New(tallowerr.CodeAuth, "authentication required")
	}
	now := m.options.Now().UTC()
	session, err := m.store.GetSessionByTokenHash(r.Context(), hashToken(cookie.Value), now)
	if err != nil {
		return Principal{}, tallowerr.New(tallowerr.CodeAuth, "authentication required")
	}
	return Principal{UserID: session.UserID, Email: session.Email, Provider: session.Provider, Roles: session.Roles}, nil
}

func (m *SessionManager) LogoutHTTP(w http.ResponseWriter, r *http.Request) error {
	if m == nil || m.store == nil {
		http.SetCookie(w, m.cookie("", time.Unix(0, 0).UTC(), -1))
		return nil
	}
	cookie, err := r.Cookie(m.options.CookieName)
	if err == nil && cookie.Value != "" {
		if revokeErr := m.store.RevokeSession(r.Context(), hashToken(cookie.Value), m.options.Now().UTC()); revokeErr != nil {
			return revokeErr
		}
	}
	http.SetCookie(w, m.cookie("", time.Unix(0, 0).UTC(), -1))
	return nil
}

func (m *SessionManager) cookie(value string, expires time.Time, maxAge int) *http.Cookie {
	secure := m.options.SecureCookies && !m.options.DevInsecureCookies
	return &http.Cookie{
		Name:     m.options.CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", tallowerr.Wrap(tallowerr.CodeInternal, "generate session token failed", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
