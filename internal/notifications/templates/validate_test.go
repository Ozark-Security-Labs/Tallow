package templates

import (
	"strings"
	"testing"
)

func TestTemplateValidationAndRendering(t *testing.T) {
	template := Template{
		ID:                 "high_risk_finding",
		Version:            "1",
		Description:        "Finding requiring review",
		CompatibleChannels: []Channel{ChannelEmail, ChannelTeams},
		Variables: map[string]Variable{
			"package_name": {Type: TypeString, Required: true, Redaction: RedactNone, Description: "Package"},
			"version":      {Type: TypeString, Required: true, Redaction: RedactNone, Description: "Version"},
			"severity":     {Type: TypeString, Required: true, Redaction: RedactNone, Description: "Severity"},
			"evidence_url": {Type: TypeURL, Required: true, Redaction: RedactURL, Description: "Evidence link"},
		},
		Targets: Targets{
			Email: &EmailTargets{Subject: "Tallow finding: {{ package_name }}", Text: "{{ package_name }}@{{ version }} has {{ severity }} signals: {{ evidence_url }}", HTML: "<p>{{ package_name }} {{ evidence_url }}</p>"},
			Teams: &TeamsTargets{CardJSON: `{"type":"message","text":"{{ package_name }} {{ severity }} {{ evidence_url }}"}`},
		},
	}
	if err := Validate(template); err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(template, map[string]any{"package_name": "pkg", "version": "1.0.0", "severity": "high", "evidence_url": "https://tallow.local/evidence/finding?id=abc&token=secret"})
	if err != nil {
		t.Fatal(err)
	}
	if rendered.Email == nil || !strings.Contains(rendered.Email.Text, "https://tallow.local/...") || strings.Contains(rendered.Email.Text, "token=secret") {
		t.Fatalf("email was not redacted: %#v", rendered.Email)
	}
	if rendered.Teams == nil || !strings.Contains(rendered.Teams.CardJSON, `pkg high`) {
		t.Fatalf("teams JSON was not canonical: %#v", rendered.Teams)
	}
}

func TestTemplateValidationRejectsUndeclaredVariables(t *testing.T) {
	template := Template{ID: "bad", Version: "1", CompatibleChannels: []Channel{ChannelEmail}, Variables: map[string]Variable{"package_name": {Type: TypeString, Required: true, Redaction: RedactNone, Description: "Package"}}, Targets: Targets{Email: &EmailTargets{Subject: "{{ package_name }}", Text: "{{ missing }}", HTML: "{{ package_name }}"}}}
	if err := Validate(template); err == nil || !strings.Contains(err.Error(), "undeclared") {
		t.Fatalf("expected undeclared variable error, got %v", err)
	}
}

func TestTemplateValidationRejectsRawArtifactVariables(t *testing.T) {
	template := Template{ID: "bad", Version: "1", CompatibleChannels: []Channel{ChannelEmail}, Variables: map[string]Variable{"raw_artifact_contents": {Type: TypeString, Required: true, Redaction: RedactNone, Description: "Raw artifact"}}, Targets: Targets{Email: &EmailTargets{Subject: "x", Text: "x", HTML: "x"}}}
	if err := Validate(template); err == nil || !strings.Contains(err.Error(), "raw artifact") {
		t.Fatalf("expected raw artifact rejection, got %v", err)
	}
}

func TestRenderRequiresRequiredVariables(t *testing.T) {
	template := Template{ID: "missing", Version: "1", CompatibleChannels: []Channel{ChannelEmail}, Variables: map[string]Variable{"package_name": {Type: TypeString, Required: true, Redaction: RedactNone, Description: "Package"}}, Targets: Targets{Email: &EmailTargets{Subject: "{{ package_name }}", Text: "{{ package_name }}", HTML: "{{ package_name }}"}}}
	if _, err := Render(template, map[string]any{}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required variable error, got %v", err)
	}
}
