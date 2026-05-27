package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

type AffectedDependency struct {
	Package         string `json:"package"`
	Version         string `json:"version"`
	SourceFindingID string `json:"source_finding_id"`
	Status          string `json:"status"`
	Depth           int    `json:"depth"`
	PathFingerprint string `json:"path_fingerprint"`
}
type GraphFilters struct {
	Ecosystem   string
	PackageName string
	Version     string
	Limit       int
	Offset      int
}
type GraphReader interface {
	ListAffectedDirectDependencies(context.Context, GraphFilters) ([]AffectedDependency, error)
}
type EmptyGraphStore struct{}

func (EmptyGraphStore) ListAffectedDirectDependencies(context.Context, GraphFilters) ([]AffectedDependency, error) {
	return []AffectedDependency{}, nil
}

type affectedResponse struct {
	Items []AffectedDependency `json:"items"`
}

func (s *Server) listAffectedDirectDependencies(w http.ResponseWriter, r *http.Request) {
	filters, err := parseGraphFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	items, err := s.graphStore().ListAffectedDirectDependencies(r.Context(), filters)
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "list affected dependencies failed", err))
		return
	}
	if items == nil {
		items = []AffectedDependency{}
	}
	writeJSON(w, http.StatusOK, affectedResponse{Items: items})
}
func (s *Server) graphStore() GraphReader {
	if s.Graph == nil {
		return EmptyGraphStore{}
	}
	return s.Graph
}
func parseGraphFilters(r *http.Request) (GraphFilters, error) {
	q := r.URL.Query()
	limit := 50
	offset := 0
	var err error
	if raw := q.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			return GraphFilters{}, tallowerr.New(tallowerr.CodeValidation, "limit must be 1..200")
		}
	}
	if raw := q.Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return GraphFilters{}, tallowerr.New(tallowerr.CodeValidation, "offset must be >=0")
		}
	}
	return GraphFilters{Ecosystem: q.Get("ecosystem"), PackageName: q.Get("package"), Version: q.Get("version"), Limit: limit, Offset: offset}, nil
}
