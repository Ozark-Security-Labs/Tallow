package api

import (
	"context"
	"errors"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/requestid"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func srv(checks map[string]Check) *Server {
	c := config.Default()
	return New(c, slog.Default(), checks)
}
func TestHealthReady(t *testing.T) {
	s := srv(nil)
	for _, p := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 {
			t.Fatalf("%s %d %s", p, w.Code, w.Body.String())
		}
	}
}
func TestReadyFailAndRequestID(t *testing.T) {
	s := srv(map[string]Check{"db": func(context.Context) error { return errors.New("secret dsn") }})
	r := httptest.NewRequest("GET", "/readyz", nil)
	r.Header.Set(requestid.Header, "rid")
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, r)
	if w.Code != 503 || w.Header().Get(requestid.Header) != "rid" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "request_id") {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), "secret dsn") {
		t.Fatal("leaked cause")
	}
}
func TestMetricsEndpoint(t *testing.T) {
	s := srv(nil)
	s.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tallow_") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

var _ = http.MethodGet
