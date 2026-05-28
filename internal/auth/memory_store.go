package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[string]Session{}}
}

func (s *MemorySessionStore) CreateSession(_ context.Context, session Session) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session.ID == "" {
		session.ID = randomID("ses")
	}
	s.sessions[session.TokenHash] = session
	return session, nil
}

func (s *MemorySessionStore) GetSessionByTokenHash(_ context.Context, tokenHash string, now time.Time) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[tokenHash]
	if !ok || !session.RevokedAt.IsZero() || !session.ExpiresAt.After(now) {
		return Session{}, ErrSessionNotFound
	}
	session.LastSeenAt = now
	s.sessions[tokenHash] = session
	return session, nil
}

func (s *MemorySessionStore) RevokeSession(_ context.Context, tokenHash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[tokenHash]
	if !ok {
		return nil
	}
	session.RevokedAt = now
	s.sessions[tokenHash] = session
	return nil
}

func randomID(prefix string) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return prefix + "_unavailable"
	}
	return prefix + "_" + hex.EncodeToString(buf)
}
