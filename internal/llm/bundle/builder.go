package bundle

import (
	"fmt"
	"sort"

	"github.com/Ozark-Security-Labs/Tallow/internal/llm"
	"github.com/Ozark-Security-Labs/Tallow/internal/redaction"
)

type Bundle struct {
	Subject              llm.Subject    `json:"subject"`
	Findings             []llm.Finding  `json:"findings"`
	Evidence             []llm.Evidence `json:"evidence"`
	RedactionAudit       map[string]int `json:"redaction_audit"`
	OmittedEvidenceCount int            `json:"omitted_evidence_count"`
}
type Builder struct {
	Redactor         redaction.DefaultRedactor
	MaxEvidenceItems int
	MaxSnippetBytes  int
}

func (b Builder) Build(input llm.GenerateInput) (Bundle, error) {
	if len(input.Findings) == 0 {
		return Bundle{}, fmt.Errorf("deterministic findings required")
	}
	if b.MaxEvidenceItems <= 0 {
		b.MaxEvidenceItems = 20
	}
	if b.MaxSnippetBytes <= 0 {
		b.MaxSnippetBytes = 4096
	}
	sort.Slice(input.Findings, func(i, j int) bool { return input.Findings[i].ID < input.Findings[j].ID })
	sort.Slice(input.Evidence, func(i, j int) bool { return input.Evidence[i].ID < input.Evidence[j].ID })
	audit := map[string]int{}
	outEvidence := []llm.Evidence{}
	for idx, ev := range input.Evidence {
		if idx >= b.MaxEvidenceItems {
			continue
		}
		if ev.Kind == "raw_artifact" {
			return Bundle{}, fmt.Errorf("raw artifact content refused")
		}
		res := b.Redactor.RedactText(ev.Text, redaction.Options{MaxBytes: b.MaxSnippetBytes})
		for _, f := range res.Findings {
			audit[f.Type] += f.Count
		}
		outEvidence = append(outEvidence, llm.Evidence{ID: ev.ID, Kind: ev.Kind, Path: ev.Path, Text: res.Text})
	}
	omitted := len(input.Evidence) - len(outEvidence)
	if omitted < 0 {
		omitted = 0
	}
	return Bundle{Subject: input.Subject, Findings: input.Findings, Evidence: outEvidence, RedactionAudit: audit, OmittedEvidenceCount: omitted}, nil
}
