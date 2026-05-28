package llm

import (
	"context"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/llm/provider"
	"strings"
	"testing"
)

type captureProvider struct{ req provider.Request }

func (c *captureProvider) Name() string { return "capture" }
func (c *captureProvider) Type() string { return "fake" }
func (c *captureProvider) Generate(ctx context.Context, req provider.Request) (provider.Response, error) {
	c.req = req
	return (&provider.Fake{ProviderName: "capture", ModelName: req.Model, Output: map[string]any{"schema_version": "v1", "verdict": "needs_review", "confidence_label": "medium", "summary": "ok", "attack_hypothesis": "x", "supporting_evidence_ids": []string{"E-1"}, "benign_explanations": []string{}, "recommended_actions": []string{}, "uncertainty_notes": []string{}, "canonical_severity_restated": "high", "severity_override_attempted": false}}).Generate(ctx, req)
}

func TestServiceRedactsAndValidatesBeforeReturn(t *testing.T) {
	cfg := config.DefaultLLMConfig()
	cfg.Enabled = true
	cfg.Provider = config.LLMProviderConfig{Type: config.LLMProviderFake, Name: "capture", Model: "test"}
	cap := &captureProvider{}
	_, err := (Service{Config: cfg, Provider: cap}).GenerateNarrative(context.Background(), GenerateInput{Subject: Subject{PackageName: "@private/pkg", Version: "1.0.0"}, CanonicalSeverity: "high", Findings: []Finding{{ID: "F-1", RuleID: "r", CanonicalSeverity: "high"}}, Evidence: []Evidence{{ID: "E-1", Kind: "readme", Path: "/home/alice/private/README.md", Text: "admin@example.com token=abcdefghijklmnop"}}})
	if err != nil {
		t.Fatal(err)
	}
	body := cap.req.Messages[1].Content
	if strings.Contains(body, "admin@example.com") || strings.Contains(body, "abcdefghijklmnop") || strings.Contains(body, "@private/pkg") || strings.Contains(body, "/home/alice") {
		t.Fatalf("unredacted provider request: %s", body)
	}
}
func TestServiceRejectsRawArtifactAndInvalidProviderOutput(t *testing.T) {
	cfg := config.DefaultLLMConfig()
	cfg.Enabled = true
	cfg.Provider = config.LLMProviderConfig{Type: config.LLMProviderFake, Name: "fake", Model: "test"}
	_, err := (Service{Config: cfg, Provider: &provider.Fake{}}).GenerateNarrative(context.Background(), GenerateInput{Findings: []Finding{{ID: "F-1"}}, Evidence: []Evidence{{ID: "E-1", Kind: "raw_artifact", Text: "raw"}}})
	if err == nil {
		t.Fatal("expected raw artifact rejection")
	}
	bad := &provider.Fake{Output: map[string]any{"schema_version": "v1", "verdict": "needs_review", "confidence_label": "medium", "summary": "bad", "attack_hypothesis": "x", "supporting_evidence_ids": []string{"UNKNOWN"}, "benign_explanations": []string{}, "recommended_actions": []string{}, "uncertainty_notes": []string{}, "canonical_severity_restated": "high", "severity_override_attempted": false}}
	_, err = (Service{Config: cfg, Provider: bad}).GenerateNarrative(context.Background(), GenerateInput{CanonicalSeverity: "high", Findings: []Finding{{ID: "F-1", RuleID: "r", CanonicalSeverity: "high"}}, Evidence: []Evidence{{ID: "E-1", Kind: "readme", Text: "x"}}})
	if err == nil {
		t.Fatal("expected invalid provider output rejection")
	}
}
