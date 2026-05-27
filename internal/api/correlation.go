package api

import (
	"context"
	"net/http"
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
	PackageName string
	Version     string
	Limit       int
	Offset      int
}
type CorrelationReader interface {
	ListCorrelations(context.Context, CorrelationFilters) ([]CorrelationRecord, error)
}
type EmptyCorrelationStore struct{}

func (EmptyCorrelationStore) ListCorrelations(context.Context, CorrelationFilters) ([]CorrelationRecord, error) {
	return []CorrelationRecord{}, nil
}
func (s *Server) correlationStore() CorrelationReader {
	if s.Correlations == nil {
		return EmptyCorrelationStore{}
	}
	return s.Correlations
}
func (s *Server) listCorrelations(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parseLimitOffset(r, 50)
	if err != nil {
		writeError(w, r, err)
		return
	}
	items, err := s.correlationStore().ListCorrelations(r.Context(), CorrelationFilters{PackageName: r.URL.Query().Get("package"), Version: r.URL.Query().Get("version"), Limit: limit, Offset: offset})
	if err != nil {
		writeError(w, r, err)
		return
	}
	if items == nil {
		items = []CorrelationRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
