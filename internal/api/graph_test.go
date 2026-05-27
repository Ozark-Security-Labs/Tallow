package api

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/config"
)

type fakeGraphStore struct{ items []AffectedDependency }

func (f fakeGraphStore) ListAffectedDirectDependencies(_ context.Context, filters GraphFilters) ([]AffectedDependency, error) {
	if filters.Limit == 0 {
		panic("limit not parsed")
	}
	return f.items, nil
}

func TestListAffectedDirectDependencies(t *testing.T) {
	s := NewWithFindings(config.Default(), slog.Default(), nil, EmptyFindingStore{})
	s.Graph = fakeGraphStore{items: []AffectedDependency{{Package: "direct", Version: "1.0.0", SourceFindingID: "finding-1", Status: "affected_by_transitive", Depth: 1, PathFingerprint: "abc"}}}
	s.Handler = s.routes()
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/graph/affected-direct-dependencies?ecosystem=npm&package=direct&limit=10", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "affected_by_transitive") || strings.Contains(w.Body.String(), "compromised_intrinsic") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
