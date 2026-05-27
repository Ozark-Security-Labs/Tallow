package api

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/config"
)

type fakeCorrelationStore struct{ items []CorrelationRecord }

func (f fakeCorrelationStore) ListCorrelations(context.Context, CorrelationFilters) ([]CorrelationRecord, error) {
	return f.items, nil
}

func TestListCorrelationsExposesEvidence(t *testing.T) {
	s := NewWithFindings(config.Default(), slog.Default(), nil, EmptyFindingStore{})
	s.Correlations = fakeCorrelationStore{items: []CorrelationRecord{{Package: "pkg", Version: "1.0.0", SourceURL: "https://github.com/o/r", Confidence: "repository_metadata", Evidence: []map[string]string{{"source": "repository", "url": "https://github.com/o/r"}}}}}
	s.Handler = s.routes()
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/source-correlations?package=pkg&version=1.0.0", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "repository_metadata") || !strings.Contains(w.Body.String(), "evidence") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestCorrelationAliasRoutes(t *testing.T) {
	s := NewWithFindings(config.Default(), slog.Default(), nil, EmptyFindingStore{})
	s.Correlations = fakeCorrelationStore{items: []CorrelationRecord{{Package: "pkg", Version: "1.0.0", SourceURL: "https://github.com/o/r", Confidence: "repository_metadata", Evidence: []map[string]string{{"source": "repository"}}}}}
	s.Handler = s.routes()
	for _, path := range []string{"/v1/package-versions/pv1/source-correlations", "/v1/artifacts/art1/source-correlations"} {
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest("GET", path+"?limit=10", nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "repository_metadata") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
