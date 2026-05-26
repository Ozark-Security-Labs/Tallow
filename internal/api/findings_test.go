package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/config"
)

type fakeFindingStore struct {
	items []FindingRecord
}

func (f fakeFindingStore) GetFinding(_ context.Context, id string) (FindingRecord, error) {
	for _, item := range f.items {
		if item.ID == id {
			return item, nil
		}
	}
	return FindingRecord{}, ErrFindingNotFound
}

func (f fakeFindingStore) ListFindings(_ context.Context, filters FindingFilters) ([]FindingRecord, error) {
	var out []FindingRecord
	for _, item := range f.items {
		if filters.Ecosystem != "" && item.Ecosystem != filters.Ecosystem {
			continue
		}
		if filters.PackageName != "" && item.PackageName != filters.PackageName {
			continue
		}
		if filters.Version != "" && item.Version != filters.Version {
			continue
		}
		if filters.SeverityHint != "" && item.SeverityHint != filters.SeverityHint {
			continue
		}
		if filters.Confidence != "" && item.Confidence != filters.Confidence {
			continue
		}
		if filters.Status != "" && item.Status != filters.Status {
			continue
		}
		if !filters.CursorCreatedAt.IsZero() {
			if !item.CreatedAt.Before(filters.CursorCreatedAt) &&
				!(item.CreatedAt.Equal(filters.CursorCreatedAt) && item.ID < filters.CursorID) {
				continue
			}
		}
		out = append(out, item)
		if len(out) == filters.Limit {
			break
		}
	}
	return out, nil
}

func findingSrv(items []FindingRecord) *Server {
	return NewWithFindings(config.Default(), slog.Default(), nil, fakeFindingStore{items: items})
}

func sampleFinding(id string, createdAt time.Time) FindingRecord {
	return FindingRecord{
		ID:              id,
		RunID:           "run_1",
		RuleID:          "npm.lifecycle.install_script",
		RuleVersion:     "1.0.0",
		AnalyzerID:      "builtin.rules",
		AnalyzerVersion: "0.1.0",
		Ecosystem:       "npm",
		PackageName:     "pkg",
		Version:         "1.0.0",
		Category:        "script",
		SeverityHint:    "medium",
		Confidence:      "high",
		Title:           "title",
		Summary:         "summary",
		Subject:         json.RawMessage(`{"ecosystem":"npm","package_name":"pkg"}`),
		Evidence:        json.RawMessage(`[{"kind":"file","artifact_id":"art","path":"package.json"}]`),
		Tags:            []string{"npm"},
		Status:          "open",
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}
}

func TestListFindingsEmpty(t *testing.T) {
	s := findingSrv(nil)
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/findings", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestListFindingsFiltersAndPagination(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	older := sampleFinding("fin_v1_00000000000000000000000000000001", now.Add(-time.Hour))
	newer := sampleFinding("fin_v1_00000000000000000000000000000002", now)
	newer.PackageName = "other"
	s := findingSrv([]FindingRecord{newer, older})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(
		"GET", "/v1/findings?ecosystem=npm&package=pkg&severity_hint=medium&limit=1", nil,
	)
	s.Handler.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), older.ID) || strings.Contains(w.Body.String(), newer.ID) {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "next_cursor") {
		t.Fatal(w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"evidence_count":1`) || strings.Contains(w.Body.String(), `"evidence":`) {
		t.Fatal(w.Body.String())
	}
}

func TestFindingCursorFiltersAfterLastSeen(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	newer := sampleFinding("fin_v1_00000000000000000000000000000002", now)
	older := sampleFinding("fin_v1_00000000000000000000000000000001", now.Add(-time.Hour))
	s := findingSrv([]FindingRecord{newer, older})
	cursor := findingCursorForTest(newer.CreatedAt, newer.ID)

	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/findings?cursor="+cursor, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), older.ID) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestGetFindingAndNotFound(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	item := sampleFinding("fin_v1_00000000000000000000000000000001", now)
	s := findingSrv([]FindingRecord{item})

	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/findings/"+item.ID, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"analyzer_id":"builtin.rules"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/v1/findings/missing", nil))
	if w.Code != 404 || !strings.Contains(w.Body.String(), "not_found") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestListFindingsRejectsInvalidLimitAndCursor(t *testing.T) {
	s := findingSrv(nil)
	for _, path := range []string{"/v1/findings?limit=999", "/v1/findings?cursor=bad"} {
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
