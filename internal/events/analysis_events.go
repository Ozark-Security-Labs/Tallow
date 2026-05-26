package events

import (
	"encoding/json"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

type AnalysisEvent struct {
	JobID           string    `json:"job_id"`
	RunID           string    `json:"run_id"`
	Status          string    `json:"status"`
	AnalyzerID      string    `json:"analyzer_id,omitempty"`
	AnalyzerVersion string    `json:"analyzer_version,omitempty"`
	RulesetVersion  string    `json:"ruleset_version,omitempty"`
	FindingsEmitted int       `json:"findings_emitted"`
	ErrorCode       string    `json:"error_code,omitempty"`
	ErrorMessage    string    `json:"error_message,omitempty"`
	CompletedAt     time.Time `json:"completed_at"`
}

func (a AnalysisEvent) Validate(eventType string) error {
	if a.JobID == "" || a.RunID == "" || a.Status == "" || a.CompletedAt.IsZero() {
		return tallowerr.New(tallowerr.CodeValidation, "analysis event missing required field")
	}
	switch eventType {
	case "analysis.completed":
		if a.Status != "ok" {
			return tallowerr.New(tallowerr.CodeValidation, "completed analysis event requires ok status")
		}
	case "analysis.failed":
		if a.Status != "failed" || a.ErrorCode == "" || a.ErrorMessage == "" {
			return tallowerr.New(tallowerr.CodeValidation, "failed analysis event requires error")
		}
	default:
		return tallowerr.New(tallowerr.CodeValidation, "unknown analysis event type")
	}
	return nil
}

func NewAnalysisEnvelope(eventType string, a AnalysisEvent) (Envelope, error) {
	if err := a.Validate(eventType); err != nil {
		return Envelope{}, err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return Envelope{}, err
	}
	return NewEnvelope(eventType, b), nil
}
