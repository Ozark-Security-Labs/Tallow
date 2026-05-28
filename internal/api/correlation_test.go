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

type fakeCorrelationStore struct {
	items            []CorrelationRecord
	packageVersionID string
	artifactID       string
}

func (f *fakeCorrelationStore) ListCorrelations(context.Context, CorrelationFilters) ([]CorrelationRecord, error) {
	return f.items, nil
}
func (f *fakeCorrelationStore) ListCorrelationsByPackageVersion(_ context.Context, id string, filters CorrelationFilters) ([]CorrelationRecord, error) {
	f.packageVersionID = id
	if filters.PackageVersionID != id {
		return nil, nil
	}
	return f.items, nil
}
func (f *fakeCorrelationStore) ListCorrelationsByArtifact(_ context.Context, id string, filters CorrelationFilters) ([]CorrelationRecord, error) {
	f.artifactID = id
	if filters.ArtifactID != id {
		return nil, nil
	}
	return f.items, nil
}

func TestListCorrelationsExposesEvidence(t *testing.T) {
	s := authorizeTestServer(NewWithFindings(config.Default(), slog.Default(), nil, EmptyFindingStore{}), auth.RoleViewer)
	s.Correlations = &fakeCorrelationStore{items: []CorrelationRecord{{Package: "pkg", Version: "1.0.0", SourceURL: "https://github.com/o/r", Confidence: "repository_metadata", Evidence: []map[string]string{{"source": "repository", "url": "https://github.com/o/r"}}}}}
	s.Handler = s.routes()
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/source-correlations?package=pkg&version=1.0.0", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "repository_metadata") || !strings.Contains(w.Body.String(), "evidence") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestCorrelationAliasRoutesFilterByPathID(t *testing.T) {
	store := &fakeCorrelationStore{items: []CorrelationRecord{{Package: "pkg", Version: "1.0.0", SourceURL: "https://github.com/o/r", Confidence: "repository_metadata", Evidence: []map[string]string{{"source": "repository"}}}}}
	s := authorizeTestServer(NewWithFindings(config.Default(), slog.Default(), nil, EmptyFindingStore{}), auth.RoleViewer)
	s.Correlations = store
	s.Handler = s.routes()
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/package-versions/pv1/source-correlations?limit=10", nil))
	if w.Code != 200 || store.packageVersionID != "pv1" || !strings.Contains(w.Body.String(), "repository_metadata") {
		t.Fatalf("package route: %d %s id=%s", w.Code, w.Body.String(), store.packageVersionID)
	}
	w = httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/artifacts/art1/source-correlations?limit=10", nil))
	if w.Code != 200 || store.artifactID != "art1" || !strings.Contains(w.Body.String(), "repository_metadata") {
		t.Fatalf("artifact route: %d %s id=%s", w.Code, w.Body.String(), store.artifactID)
	}
}
