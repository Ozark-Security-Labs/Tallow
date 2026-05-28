package llm

import "time"

type Evidence struct{ ID, Kind, Path, Text string }
type Finding struct {
	ID, RuleID, Title, CanonicalSeverity string
	EvidenceIDs                          []string
}
type Subject struct{ Ecosystem, PackageName, Version string }

type GenerateInput struct {
	Subject           Subject
	Findings          []Finding
	Evidence          []Evidence
	CanonicalSeverity string
}

type Narrative struct {
	ID                    string    `json:"id"`
	Source                string    `json:"source"`
	Summary               string    `json:"summary"`
	AttackHypothesis      string    `json:"attack_hypothesis"`
	EvidenceIDs           []string  `json:"evidence_ids"`
	RecommendedActions    []string  `json:"recommended_actions"`
	ProviderType          string    `json:"provider_type"`
	ProviderName          string    `json:"provider_name"`
	Model                 string    `json:"model"`
	PromptTemplateVersion string    `json:"prompt_template_version"`
	InputDigest           string    `json:"input_digest"`
	CreatedAt             time.Time `json:"created_at"`
}
