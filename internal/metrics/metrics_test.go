package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsSafe(t *testing.T) {
	m := New()
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/token-secret-value?token=secret", strings.NewReader("payload")))
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	s := w.Body.String()
	if !strings.Contains(s, "tallow_http_requests_total") {
		t.Fatal(s)
	}
	if strings.Contains(s, "secret") || strings.Contains(s, "payload") || strings.Contains(s, "token-secret-value") {
		t.Fatal("leaked payload/query/path")
	}
	if !strings.Contains(s, `path="unknown"`) {
		t.Fatal(s)
	}
}
