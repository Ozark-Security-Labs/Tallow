package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"github.com/go-chi/chi/v5"
)

var ErrFindingNotFound = errors.New("finding not found")

type FindingRecord struct {
	ID              string          `json:"id"`
	RunID           string          `json:"run_id"`
	RuleID          string          `json:"rule_id"`
	RuleVersion     string          `json:"rule_version"`
	AnalyzerID      string          `json:"analyzer_id"`
	AnalyzerVersion string          `json:"analyzer_version"`
	Ecosystem       string          `json:"ecosystem"`
	PackageName     string          `json:"package_name"`
	Version         string          `json:"version,omitempty"`
	ArtifactID      string          `json:"artifact_id,omitempty"`
	SnapshotID      string          `json:"snapshot_id,omitempty"`
	Category        string          `json:"category"`
	SeverityHint    string          `json:"severity_hint"`
	Confidence      string          `json:"confidence"`
	Title           string          `json:"title"`
	Summary         string          `json:"summary"`
	Subject         json.RawMessage `json:"subject"`
	Evidence        json.RawMessage `json:"evidence"`
	Tags            []string        `json:"tags"`
	Status          string          `json:"status"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type FindingSummary struct {
	ID              string    `json:"id"`
	RunID           string    `json:"run_id"`
	RuleID          string    `json:"rule_id"`
	RuleVersion     string    `json:"rule_version"`
	AnalyzerID      string    `json:"analyzer_id"`
	AnalyzerVersion string    `json:"analyzer_version"`
	Ecosystem       string    `json:"ecosystem"`
	PackageName     string    `json:"package_name"`
	Version         string    `json:"version,omitempty"`
	ArtifactID      string    `json:"artifact_id,omitempty"`
	SnapshotID      string    `json:"snapshot_id,omitempty"`
	Category        string    `json:"category"`
	SeverityHint    string    `json:"severity_hint"`
	Confidence      string    `json:"confidence"`
	Title           string    `json:"title"`
	Summary         string    `json:"summary"`
	EvidenceCount   int       `json:"evidence_count"`
	Tags            []string  `json:"tags"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type FindingFilters struct {
	Ecosystem       string
	PackageName     string
	Version         string
	SeverityHint    string
	Confidence      string
	Category        string
	RuleID          string
	Status          string
	ArtifactID      string
	SnapshotID      string
	CreatedAfter    time.Time
	CreatedBefore   time.Time
	CursorCreatedAt time.Time
	CursorID        string
	Limit           int
}

type FindingReader interface {
	GetFinding(context.Context, string) (FindingRecord, error)
	ListFindings(context.Context, FindingFilters) ([]FindingRecord, error)
}

type FindingWriter interface {
	UpdateFindingStatus(context.Context, string, string) (FindingRecord, error)
}

type EmptyFindingStore struct{}

func (EmptyFindingStore) GetFinding(context.Context, string) (FindingRecord, error) {
	return FindingRecord{}, ErrFindingNotFound
}

func (EmptyFindingStore) ListFindings(context.Context, FindingFilters) ([]FindingRecord, error) {
	return []FindingRecord{}, nil
}

type findingListResponse struct {
	Items      []FindingSummary `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	filters, err := parseFindingFilters(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	items, err := s.findingStore().ListFindings(r.Context(), filters)
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "list findings failed", err))
		return
	}
	if items == nil {
		items = []FindingRecord{}
	}
	response := findingListResponse{Items: findingSummaries(items)}
	if len(items) == filters.Limit && len(items) > 0 {
		last := items[len(items)-1]
		response.NextCursor = encodeFindingCursor(last.CreatedAt, last.ID)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, r, tallowerr.New(tallowerr.CodeValidation, "finding id required"))
		return
	}
	record, err := s.findingStore().GetFinding(r.Context(), id)
	if errors.Is(err, ErrFindingNotFound) {
		writeError(w, r, tallowerr.New(tallowerr.CodeNotFound, "finding not found"))
		return
	}
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "get finding failed", err))
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) updateFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, r, tallowerr.New(tallowerr.CodeValidation, "invalid finding update body"))
		return
	}
	if err := validateFindingStatus(payload.Status); err != nil || payload.Status == "" {
		writeError(w, r, tallowerr.New(tallowerr.CodeValidation, "invalid finding status"))
		return
	}
	writer, ok := s.Findings.(FindingWriter)
	if !ok {
		writeError(w, r, tallowerr.New(tallowerr.CodeNotImplemented, "finding updates are not configured"))
		return
	}
	record, err := writer.UpdateFindingStatus(r.Context(), id, payload.Status)
	if errors.Is(err, ErrFindingNotFound) {
		writeError(w, r, tallowerr.New(tallowerr.CodeNotFound, "finding not found"))
		return
	}
	if err != nil {
		writeError(w, r, tallowerr.Wrap(tallowerr.CodeDatabaseUnavailable, "update finding failed", err))
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) findingStore() FindingReader {
	if s.Findings == nil {
		return EmptyFindingStore{}
	}
	return s.Findings
}

func parseFindingFilters(r *http.Request) (FindingFilters, error) {
	q := r.URL.Query()
	limit := 50
	if raw := q.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			return FindingFilters{}, tallowerr.New(tallowerr.CodeValidation, "limit must be 1..200")
		}
		limit = parsed
	}
	filters := FindingFilters{
		Ecosystem:    q.Get("ecosystem"),
		PackageName:  q.Get("package"),
		Version:      q.Get("version"),
		SeverityHint: q.Get("severity_hint"),
		Confidence:   q.Get("confidence"),
		Category:     q.Get("category"),
		RuleID:       q.Get("rule_id"),
		Status:       q.Get("status"),
		ArtifactID:   q.Get("artifact_id"),
		SnapshotID:   q.Get("snapshot_id"),
		Limit:        limit,
	}
	var err error
	if filters.CreatedAfter, err = parseOptionalTime(q.Get("created_after")); err != nil {
		return FindingFilters{}, err
	}
	if filters.CreatedBefore, err = parseOptionalTime(q.Get("created_before")); err != nil {
		return FindingFilters{}, err
	}
	if raw := q.Get("cursor"); raw != "" {
		filters.CursorCreatedAt, filters.CursorID, err = decodeFindingCursor(raw)
		if err != nil {
			return FindingFilters{}, err
		}
	}
	return filters, nil
}

func findingSummaries(items []FindingRecord) []FindingSummary {
	summaries := make([]FindingSummary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, FindingSummary{
			ID:              item.ID,
			RunID:           item.RunID,
			RuleID:          item.RuleID,
			RuleVersion:     item.RuleVersion,
			AnalyzerID:      item.AnalyzerID,
			AnalyzerVersion: item.AnalyzerVersion,
			Ecosystem:       item.Ecosystem,
			PackageName:     item.PackageName,
			Version:         item.Version,
			ArtifactID:      item.ArtifactID,
			SnapshotID:      item.SnapshotID,
			Category:        item.Category,
			SeverityHint:    item.SeverityHint,
			Confidence:      item.Confidence,
			Title:           item.Title,
			Summary:         item.Summary,
			EvidenceCount:   evidenceCount(item.Evidence),
			Tags:            item.Tags,
			Status:          item.Status,
			CreatedAt:       item.CreatedAt,
			UpdatedAt:       item.UpdatedAt,
		})
	}
	return summaries
}

func evidenceCount(raw json.RawMessage) int {
	var evidence []json.RawMessage
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return 0
	}
	return len(evidence)
}

func parseOptionalTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, tallowerr.New(tallowerr.CodeValidation, "time filters must be RFC3339")
	}
	return parsed, nil
}

func encodeFindingCursor(createdAt time.Time, id string) string {
	payload, _ := json.Marshal(struct {
		CreatedAt string `json:"created_at"`
		ID        string `json:"id"`
	}{CreatedAt: createdAt.UTC().Format(time.RFC3339Nano), ID: id})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeFindingCursor(raw string) (time.Time, string, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", tallowerr.New(tallowerr.CodeValidation, "invalid cursor")
	}
	var payload struct {
		CreatedAt string `json:"created_at"`
		ID        string `json:"id"`
	}
	if err := json.Unmarshal(data, &payload); err != nil || payload.ID == "" || payload.CreatedAt == "" {
		return time.Time{}, "", tallowerr.New(tallowerr.CodeValidation, "invalid cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil {
		return time.Time{}, "", tallowerr.New(tallowerr.CodeValidation, "invalid cursor")
	}
	return createdAt, payload.ID, nil
}

func findingCursorForTest(createdAt time.Time, id string) string {
	return encodeFindingCursor(createdAt, id)
}

func validateFindingStatus(status string) error {
	switch status {
	case "", "open", "triaged", "dismissed", "fixed":
		return nil
	default:
		return fmt.Errorf("invalid finding status %q", status)
	}
}
