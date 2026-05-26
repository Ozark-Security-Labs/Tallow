package analyzers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/db/sqlc"
	"github.com/jackc/pgx/v5/pgtype"
)

type SQLRecorder struct {
	Queries *sqlc.Queries
}

func (r SQLRecorder) RecordRun(ctx context.Context, run AnalyzerRunRecord) error {
	_, err := r.Queries.InsertAnalyzerRun(ctx, sqlc.InsertAnalyzerRunParams{
		ID:              run.ID,
		JobID:           run.JobID,
		AnalyzerID:      fallback(run.AnalyzerID, "unknown"),
		AnalyzerVersion: fallback(run.AnalyzerVersion, "unknown"),
		RulesetVersion:  fallback(run.RulesetVersion, "unknown"),
		Status:          run.Status,
		StartedAt:       timestamptz(run.StartedAt),
		FinishedAt:      timestamptz(run.FinishedAt),
		DurationMs:      int8Value(run.Duration.Milliseconds()),
		InputJson:       run.InputJSON,
		OutputJson:      nullableJSON(run.OutputJSON),
		ErrorJson:       nullableJSON(run.ErrorJSON),
	})
	return err
}

func (r SQLRecorder) RecordFindings(ctx context.Context, runID string, findings []Finding) error {
	for _, finding := range findings {
		subjectJSON, err := json.Marshal(finding.Subject)
		if err != nil {
			return err
		}
		evidenceJSON, err := json.Marshal(finding.Evidence)
		if err != nil {
			return err
		}
		_, err = r.Queries.UpsertFinding(ctx, sqlc.UpsertFindingParams{
			ID:              finding.ID,
			RunID:           runID,
			RuleID:          finding.RuleID,
			RuleVersion:     finding.RuleVersion,
			AnalyzerID:      finding.AnalyzerID,
			AnalyzerVersion: finding.AnalyzerVersion,
			Ecosystem:       finding.Subject.Ecosystem,
			PackageName:     finding.Subject.PackageName,
			Version:         textPtr(finding.Subject.Version),
			ArtifactID:      textPtr(finding.Subject.ArtifactID),
			SnapshotID:      textPtr(finding.Subject.SnapshotID),
			Category:        finding.Category,
			SeverityHint:    finding.SeverityHint,
			Confidence:      finding.Confidence,
			Title:           finding.Title,
			Summary:         finding.Summary,
			SubjectJson:     subjectJSON,
			EvidenceJson:    evidenceJSON,
			Tags:            finding.Tags,
			Status:          "open",
			CreatedAt:       timestamptz(finding.CreatedAt),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func fallback(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func timestamptz(value time.Time) pgtype.Timestamptz {
	if value.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func int8Value(value int64) pgtype.Int8 {
	return pgtype.Int8{Int64: value, Valid: true}
}

func nullableJSON(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return value
}

func textPtr(value *string) pgtype.Text {
	if value == nil || *value == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *value, Valid: true}
}
