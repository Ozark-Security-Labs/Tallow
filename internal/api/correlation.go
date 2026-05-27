package api

import (
	"context"
	"net/http"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"github.com/go-chi/chi/v5"
)

type CorrelationRecord struct {
	Package    string `json:"package"`
	Version    string `json:"version"`
	SourceURL  string `json:"source_url"`
	Revision   string `json:"revision,omitempty"`
	Confidence string `json:"confidence"`
	Evidence   any    `json:"evidence"`
}
type CorrelationFilters struct {
	PackageName      string
	Version          string
	PackageVersionID string
	ArtifactID       string
	Limit            int
	Offset           int
}
type CorrelationReader interface {
	ListCorrelations(context.Context, CorrelationFilters) ([]CorrelationRecord, error)
	ListCorrelationsByPackageVersion(context.Context, string, CorrelationFilters) ([]CorrelationRecord, error)
	ListCorrelationsByArtifact(context.Context, string, CorrelationFilters) ([]CorrelationRecord, error)
}
type EmptyCorrelationStore struct{}

func (EmptyCorrelationStore) ListCorrelations(context.Context, CorrelationFilters) ([]CorrelationRecord, error) {
	return []CorrelationRecord{}, nil
}
func (EmptyCorrelationStore) ListCorrelationsByPackageVersion(context.Context, string, CorrelationFilters) ([]CorrelationRecord, error) {
	return []CorrelationRecord{}, nil
}
func (EmptyCorrelationStore) ListCorrelationsByArtifact(context.Context, string, CorrelationFilters) ([]CorrelationRecord, error) {
	return []CorrelationRecord{}, nil
}
func (s *Server) correlationStore() CorrelationReader {
	if s.Correlations == nil {
		return EmptyCorrelationStore{}
	}
	return s.Correlations
}

func parseCorrelationFilters(r *http.Request) (CorrelationFilters, error) {
	limit, offset, err := parseLimitOffset(r, 50)
	if err != nil {
		return CorrelationFilters{}, err
	}
	return CorrelationFilters{PackageName: r.URL.Query().Get("package"), Version: r.URL.Query().Get("version"), Limit: limit, Offset: offset}, nil
}
func (s *Server) listCorrelations(w http.ResponseWriter, r *http.Request) {
	filters, err := parseCorrelationFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	items, err := s.correlationStore().ListCorrelations(r.Context(), filters)
	s.writeCorrelationItems(w, r, items, err)
}
func (s *Server) listPackageVersionCorrelations(w http.ResponseWriter, r *http.Request) {
	filters, err := parseCorrelationFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	filters.PackageVersionID = id
	items, err := s.correlationStore().ListCorrelationsByPackageVersion(r.Context(), id, filters)
	s.writeCorrelationItems(w, r, items, err)
}
func (s *Server) listArtifactCorrelations(w http.ResponseWriter, r *http.Request) {
	filters, err := parseCorrelationFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	filters.ArtifactID = id
	items, err := s.correlationStore().ListCorrelationsByArtifact(r.Context(), id, filters)
	s.writeCorrelationItems(w, r, items, err)
}
func (s *Server) writeCorrelationItems(w http.ResponseWriter, r *http.Request, items []CorrelationRecord, err error) {
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "list source correlations failed", err))
		return
	}
	if items == nil {
		items = []CorrelationRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
