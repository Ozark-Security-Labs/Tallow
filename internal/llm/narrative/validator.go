package narrative

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidJSON = errors.New("invalid llm narrative json")

type Output struct {
	SchemaVersion             string   `json:"schema_version"`
	Verdict                   string   `json:"verdict"`
	ConfidenceLabel           string   `json:"confidence_label"`
	Summary                   string   `json:"summary"`
	AttackHypothesis          string   `json:"attack_hypothesis"`
	SupportingEvidenceIDs     []string `json:"supporting_evidence_ids"`
	BenignExplanations        []string `json:"benign_explanations"`
	RecommendedActions        []string `json:"recommended_actions"`
	UncertaintyNotes          []string `json:"uncertainty_notes"`
	CanonicalSeverityRestated string   `json:"canonical_severity_restated"`
	SeverityOverrideAttempted bool     `json:"severity_override_attempted"`
	RuleID                    string   `json:"rule_id,omitempty"`
}

type Context struct {
	CanonicalSeverity string
	RuleIDs           []string
	EvidenceIDs       []string
}

func ParseAndValidate(raw []byte, ctx Context) (Output, error) {
	var out Output
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return Output{}, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if out.SchemaVersion != "v1" || out.Summary == "" {
		return Output{}, fmt.Errorf("invalid narrative output schema")
	}
	if out.SeverityOverrideAttempted {
		return Output{}, fmt.Errorf("severity override attempted")
	}
	if ctx.CanonicalSeverity != "" && out.CanonicalSeverityRestated != "" && out.CanonicalSeverityRestated != ctx.CanonicalSeverity {
		return Output{}, fmt.Errorf("canonical severity mismatch")
	}
	if out.RuleID != "" && !contains(ctx.RuleIDs, out.RuleID) {
		return Output{}, fmt.Errorf("rule_id change attempted")
	}
	allowed := map[string]bool{}
	for _, id := range ctx.EvidenceIDs {
		allowed[id] = true
	}
	for _, id := range out.SupportingEvidenceIDs {
		if !allowed[id] {
			return Output{}, fmt.Errorf("unknown evidence id %q", id)
		}
	}
	return out, nil
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
