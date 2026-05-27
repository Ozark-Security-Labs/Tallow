package findings

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/api"
	"github.com/Ozark-Security-Labs/Tallow/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type SQLStore struct {
	Queries *sqlc.Queries
}

func NewSQLStore(q *sqlc.Queries) SQLStore { return SQLStore{Queries: q} }

func (s SQLStore) GetFinding(ctx context.Context, id string) (api.FindingRecord, error) {
	row, err := s.Queries.GetFinding(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return api.FindingRecord{}, api.ErrFindingNotFound
		}
		return api.FindingRecord{}, err
	}
	return fromSQL(row), nil
}

func (s SQLStore) ListFindings(
	ctx context.Context,
	filters api.FindingFilters,
) ([]api.FindingRecord, error) {
	rows, err := s.Queries.ListFindings(ctx, sqlc.ListFindingsParams{
		Ecosystem:       text(filters.Ecosystem),
		PackageName:     text(filters.PackageName),
		Version:         text(filters.Version),
		SeverityHint:    text(filters.SeverityHint),
		Confidence:      text(filters.Confidence),
		Category:        text(filters.Category),
		RuleID:          text(filters.RuleID),
		Status:          text(filters.Status),
		ArtifactID:      text(filters.ArtifactID),
		SnapshotID:      text(filters.SnapshotID),
		CreatedAfter:    timestamptz(filters.CreatedAfter),
		CreatedBefore:   timestamptz(filters.CreatedBefore),
		CursorCreatedAt: timestamptz(filters.CursorCreatedAt),
		CursorID:        text(filters.CursorID),
		Limit:           int32(filters.Limit),
	})
	if err != nil {
		return nil, err
	}
	records := make([]api.FindingRecord, 0, len(rows))
	for _, row := range rows {
		records = append(records, fromSQL(row))
	}
	return records, nil
}

func fromSQL(row sqlc.Finding) api.FindingRecord {
	return api.FindingRecord{
		ID:              row.ID,
		RunID:           row.RunID,
		RuleID:          row.RuleID,
		RuleVersion:     row.RuleVersion,
		AnalyzerID:      row.AnalyzerID,
		AnalyzerVersion: row.AnalyzerVersion,
		Ecosystem:       row.Ecosystem,
		PackageName:     row.PackageName,
		Version:         textValue(row.Version),
		ArtifactID:      textValue(row.ArtifactID),
		SnapshotID:      textValue(row.SnapshotID),
		Category:        row.Category,
		SeverityHint:    row.SeverityHint,
		Confidence:      row.Confidence,
		Title:           row.Title,
		Summary:         row.Summary,
		Subject:         json.RawMessage(row.SubjectJson),
		Evidence:        json.RawMessage(row.EvidenceJson),
		Tags:            row.Tags,
		Status:          row.Status,
		CreatedAt:       row.CreatedAt.Time,
		UpdatedAt:       row.UpdatedAt.Time,
	}
}

func text(value string) pgtype.Text {
	if value == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: value, Valid: true}
}

func textValue(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func timestamptz(value time.Time) pgtype.Timestamptz {
	if value.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: value, Valid: true}
}
