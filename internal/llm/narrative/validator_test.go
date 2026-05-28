package narrative

import (
	"errors"
	"testing"
)

var valid = []byte(`{"schema_version":"v1","verdict":"needs_review","confidence_label":"medium","summary":"Review evidence.","attack_hypothesis":"Suspicious install script.","supporting_evidence_ids":["E-1"],"benign_explanations":["Could be build tooling."],"recommended_actions":["Review deterministic evidence."],"uncertainty_notes":["No maintainer confirmation."],"canonical_severity_restated":"high","severity_override_attempted":false}`)

func TestParseAndValidateNarrativeOutput(t *testing.T) {
	out, err := ParseAndValidate(valid, Context{CanonicalSeverity: "high", EvidenceIDs: []string{"E-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.AttackHypothesis == "" || len(out.RecommendedActions) == 0 || len(out.UncertaintyNotes) == 0 {
		t.Fatalf("missing fields: %+v", out)
	}
}
func TestInvalidJSONTypedError(t *testing.T) {
	_, err := ParseAndValidate([]byte(`not json`), Context{})
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("got %v", err)
	}
}
func TestRejectsSeverityAndRuleChanges(t *testing.T) {
	bad := []byte(`{"schema_version":"v1","verdict":"needs_review","confidence_label":"medium","summary":"x","attack_hypothesis":"x","supporting_evidence_ids":[],"benign_explanations":[],"recommended_actions":[],"uncertainty_notes":[],"canonical_severity_restated":"critical","severity_override_attempted":false}`)
	if _, err := ParseAndValidate(bad, Context{CanonicalSeverity: "high"}); err == nil {
		t.Fatal("expected severity mismatch")
	}
	badRule := []byte(`{"schema_version":"v1","verdict":"needs_review","confidence_label":"medium","summary":"x","attack_hypothesis":"x","supporting_evidence_ids":[],"benign_explanations":[],"recommended_actions":[],"uncertainty_notes":[],"canonical_severity_restated":"high","severity_override_attempted":false,"rule_id":"other"}`)
	if _, err := ParseAndValidate(badRule, Context{CanonicalSeverity: "high", RuleIDs: []string{"allowed"}}); err == nil {
		t.Fatal("expected rule mismatch")
	}
}
func TestRejectsUnknownEvidenceID(t *testing.T) {
	if _, err := ParseAndValidate(valid, Context{CanonicalSeverity: "high", EvidenceIDs: []string{"E-2"}}); err == nil {
		t.Fatal("expected unknown evidence")
	}
}

func TestRejectsMissingRequiredNarrativeFields(t *testing.T) {
	raw := []byte(`{"schema_version":"v1","summary":"partial","canonical_severity_restated":"high","severity_override_attempted":false}`)
	if _, err := ParseAndValidate(raw, Context{CanonicalSeverity: "high"}); err == nil {
		t.Fatal("expected required field rejection")
	}
}

func TestRejectsMissingSeverityOverrideField(t *testing.T) {
	raw := []byte(`{"schema_version":"v1","verdict":"needs_review","confidence_label":"medium","summary":"x","attack_hypothesis":"x","supporting_evidence_ids":[],"benign_explanations":[],"recommended_actions":[],"uncertainty_notes":[],"canonical_severity_restated":"high"}`)
	if _, err := ParseAndValidate(raw, Context{CanonicalSeverity: "high"}); err == nil {
		t.Fatal("expected missing severity_override_attempted rejection")
	}
}
