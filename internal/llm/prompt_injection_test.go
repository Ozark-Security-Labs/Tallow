package llm_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/llm"
	"github.com/Ozark-Security-Labs/Tallow/internal/llm/narrative"
	"github.com/Ozark-Security-Labs/Tallow/internal/llm/prompt"
	"github.com/Ozark-Security-Labs/Tallow/internal/redaction"
)

type fixtureManifest struct {
	SchemaVersion string         `json:"schema_version"`
	Synthetic     bool           `json:"synthetic"`
	Fixtures      []fixtureEntry `json:"fixtures"`
}
type fixtureEntry struct {
	CaseID           string   `json:"case_id"`
	File             string   `json:"file"`
	Title            string   `json:"title"`
	ThreatClass      string   `json:"threat_class"`
	Vector           string   `json:"vector"`
	ExpectedBehavior string   `json:"expected_behavior"`
	Synthetic        bool     `json:"synthetic"`
	OWASP            []string `json:"owasp"`
	MustNot          []string `json:"must_not"`
}

func TestPromptInjectionFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "llm-fixtures", "prompt-injection")
	b, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "prompt-injection-fixtures/v1" || !manifest.Synthetic {
		t.Fatalf("bad manifest: %+v", manifest)
	}
	sorted := sort.SliceIsSorted(manifest.Fixtures, func(i, j int) bool { return manifest.Fixtures[i].CaseID < manifest.Fixtures[j].CaseID })
	if !sorted {
		t.Fatal("fixtures must be sorted by case_id")
	}
	validVectors := map[string]bool{"direct": true, "indirect": true, "memory-persistent": true, "multi-turn": true}
	listed := map[string]bool{"README.md": true, "manifest.json": true}
	vectors := map[string]bool{}
	tmpl, err := prompt.Load(filepath.Join("..", "..", "configs", "llm", "prompts", "narrative-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Fixtures {
		if !entry.Synthetic || !strings.HasPrefix(entry.ThreatClass, "ASI-01/") || !validVectors[entry.Vector] || entry.ExpectedBehavior == "" || len(entry.MustNot) == 0 {
			t.Fatalf("bad entry: %+v", entry)
		}
		vectors[entry.Vector] = true
		listed[entry.File] = true
		content, err := os.ReadFile(filepath.Join(root, entry.File))
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if !strings.Contains(strings.ToLower(text), "synthetic") || !strings.Contains(strings.ToLower(text), "safe") {
			t.Fatalf("fixture must mark synthetic safe: %s", entry.File)
		}
		redacted := redaction.DefaultRedactor{}.RedactText(text, redaction.Options{MaxBytes: 4096}).Text
		rendered, err := prompt.Render(tmpl, llm.GenerateInput{Subject: llm.Subject{Ecosystem: "npm", PackageName: "fixture"}, Findings: []llm.Finding{{ID: "F-123", RuleID: "fixture.rule", CanonicalSeverity: "high"}}, Evidence: []llm.Evidence{{ID: "EV-" + entry.CaseID, Kind: "fixture", Path: entry.File, Text: redacted}}})
		if err != nil {
			t.Fatal(err)
		}
		joined := rendered.Messages[0].Content + rendered.Messages[1].Content + rendered.Messages[2].Content
		if strings.Contains(joined, "tallow_test_token_000000000000") {
			t.Fatalf("fake secret was not redacted in %s", entry.File)
		}
		evidenceIdx := strings.Index(joined, "<untrusted_evidence")
		if evidenceIdx < 0 {
			t.Fatalf("missing untrusted evidence block for %s", entry.File)
		}
		if strings.Index(strings.ToLower(joined), "hostile") > evidenceIdx {
			t.Fatalf("safety instructions after evidence for %s", entry.File)
		}
	}
	for _, want := range []string{"direct", "indirect", "memory-persistent", "multi-turn"} {
		if !vectors[want] {
			t.Fatalf("missing vector %s", want)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() && !listed[e.Name()] {
			t.Fatalf("unlisted fixture file %s", e.Name())
		}
	}
}

func TestPromptInjectionAdversarialOutputsRejected(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"schema_version":"v1","verdict":"needs_review","confidence_label":"high","summary":"safe","attack_hypothesis":"x","supporting_evidence_ids":["E-1"],"benign_explanations":[],"recommended_actions":[],"uncertainty_notes":[],"canonical_severity_restated":"critical","severity_override_attempted":false}`),
		[]byte(`{"schema_version":"v1","verdict":"needs_review","confidence_label":"high","summary":"safe","attack_hypothesis":"x","supporting_evidence_ids":["UNKNOWN"],"benign_explanations":[],"recommended_actions":[],"uncertainty_notes":[],"canonical_severity_restated":"high","severity_override_attempted":false}`),
		[]byte(`not-json markdown instead`),
	}
	for _, raw := range cases {
		if _, err := narrative.ParseAndValidate(raw, narrative.Context{CanonicalSeverity: "high", EvidenceIDs: []string{"E-1"}}); err == nil {
			t.Fatalf("adversarial output accepted: %s", raw)
		}
	}
}
