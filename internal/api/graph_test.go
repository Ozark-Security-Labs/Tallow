package api

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
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
	s := authorizeTestServer(NewWithFindings(config.Default(), slog.Default(), nil, EmptyFindingStore{}), auth.RoleViewer)
	s.Graph = fakeGraphStore{items: []AffectedDependency{{Package: "direct", Version: "1.0.0", SourceFindingID: "finding-1", Status: "affected_by_transitive", Depth: 1, PathFingerprint: "abc"}}}
	s.Handler = s.routes()
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/graph/affected-direct-dependencies?ecosystem=npm&package=direct&limit=10", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "affected_by_transitive") || strings.Contains(w.Body.String(), "compromised_intrinsic") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

type fakeStatusStore struct{}

func (fakeStatusStore) ListPackageVersionStatuses(_ context.Context, id string, _ GraphFilters) ([]PackageVersionStatusRecord, error) {
	return []PackageVersionStatusRecord{{ID: "status-1", PackageVersionID: id, Status: "compromised_intrinsic"}}, nil
}
func (fakeStatusStore) ListPackageVersionTransitiveImpacts(_ context.Context, id string, _ GraphFilters) ([]TransitiveImpactRecord, error) {
	return []TransitiveImpactRecord{{ID: "impact-1", AffectedPackageVersionID: id, Status: "affected_by_transitive", Depth: 1, PathFingerprint: "fp"}}, nil
}
func (fakeStatusStore) ListAffectedDependentsByStatus(_ context.Context, id string, _ GraphFilters) ([]AffectedDependency, error) {
	return []AffectedDependency{{Package: "dep", Status: "affected_by_transitive", SourceFindingID: id, Depth: 1}}, nil
}

func TestPackageStatusRoutesUseDedicatedHandlers(t *testing.T) {
	s := authorizeTestServer(NewWithFindings(config.Default(), slog.Default(), nil, EmptyFindingStore{}), auth.RoleViewer)
	s.Statuses = fakeStatusStore{}
	s.Handler = s.routes()
	cases := map[string]string{
		"/v1/package-versions/pv1/statuses":           "compromised_intrinsic",
		"/v1/package-versions/pv1/transitive-impacts": "impact-1",
		"/v1/statuses/status-1/affected-dependents":   "dep",
	}
	for path, want := range cases {
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
