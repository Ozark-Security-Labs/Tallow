package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"github.com/go-chi/chi/v5"
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
	limit, offset, err := parseLimitOffset(r, 50)
	if err != nil {
		return GraphFilters{}, err
	}
	return GraphFilters{Ecosystem: q.Get("ecosystem"), PackageName: q.Get("package"), Version: q.Get("version"), Limit: limit, Offset: offset}, nil
}

func parseLimitOffset(r *http.Request, defaultLimit int) (int, int, error) {
	q := r.URL.Query()
	limit := defaultLimit
	offset := 0
	var err error
	if raw := q.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			return 0, 0, tallowerr.New(tallowerr.CodeValidation, "limit must be 1..200")
		}
	}
	if raw := q.Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return 0, 0, tallowerr.New(tallowerr.CodeValidation, "offset must be >=0")
		}
	}
	return limit, offset, nil
}

type PackageVersionStatusRecord struct {
	ID               string `json:"id"`
	PackageVersionID string `json:"package_version_id"`
	Status           string `json:"status"`
	SourceFindingID  string `json:"source_finding_id,omitempty"`
}

type TransitiveImpactRecord struct {
	ID                       string `json:"id"`
	AffectedPackageVersionID string `json:"affected_package_version_id"`
	SourceFindingID          string `json:"source_finding_id"`
	Status                   string `json:"status"`
	Depth                    int    `json:"depth"`
	PathFingerprint          string `json:"path_fingerprint"`
}

type StatusReader interface {
	ListPackageVersionStatuses(context.Context, string, GraphFilters) ([]PackageVersionStatusRecord, error)
	ListPackageVersionTransitiveImpacts(context.Context, string, GraphFilters) ([]TransitiveImpactRecord, error)
	ListAffectedDependentsByStatus(context.Context, string, GraphFilters) ([]AffectedDependency, error)
}

type EmptyStatusStore struct{}

func (EmptyStatusStore) ListPackageVersionStatuses(context.Context, string, GraphFilters) ([]PackageVersionStatusRecord, error) {
	return []PackageVersionStatusRecord{}, nil
}
func (EmptyStatusStore) ListPackageVersionTransitiveImpacts(context.Context, string, GraphFilters) ([]TransitiveImpactRecord, error) {
	return []TransitiveImpactRecord{}, nil
}
func (EmptyStatusStore) ListAffectedDependentsByStatus(context.Context, string, GraphFilters) ([]AffectedDependency, error) {
	return []AffectedDependency{}, nil
}
func (s *Server) statusStore() StatusReader {
	if s.Statuses == nil {
		return EmptyStatusStore{}
	}
	return s.Statuses
}

func (s *Server) listPackageVersionStatuses(w http.ResponseWriter, r *http.Request) {
	filters, err := parseGraphFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	items, err := s.statusStore().ListPackageVersionStatuses(r.Context(), chi.URLParam(r, "id"), filters)
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "list package version statuses failed", err))
		return
	}
	if items == nil {
		items = []PackageVersionStatusRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
func (s *Server) listPackageVersionTransitiveImpacts(w http.ResponseWriter, r *http.Request) {
	filters, err := parseGraphFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	items, err := s.statusStore().ListPackageVersionTransitiveImpacts(r.Context(), chi.URLParam(r, "id"), filters)
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "list transitive impacts failed", err))
		return
	}
	if items == nil {
		items = []TransitiveImpactRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
func (s *Server) listAffectedDependentsByStatus(w http.ResponseWriter, r *http.Request) {
	filters, err := parseGraphFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	items, err := s.statusStore().ListAffectedDependentsByStatus(r.Context(), chi.URLParam(r, "id"), filters)
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "list affected dependents failed", err))
		return
	}
	if items == nil {
		items = []AffectedDependency{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
