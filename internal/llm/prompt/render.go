package prompt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/llm"
	"github.com/Ozark-Security-Labs/Tallow/internal/llm/provider"
)

type Rendered struct {
	Messages    []provider.Message
	InputDigest string
}

func Render(t Template, input llm.GenerateInput) (Rendered, error) {
	if err := t.Validate(); err != nil {
		return Rendered{}, err
	}
	subject := mustJSON(input.Subject)
	findings := mustJSON(input.Findings)
	constraints := mustJSON(map[string]any{"llm_may_change_severity": false, "llm_may_create_findings": false, "tools_available": []string{}})
	evidence := renderEvidence(input.Evidence)
	user := t.UserTemplate
	replacements := map[string]string{"{{subject_json}}": subject, "{{findings_json}}": findings, "{{constraints_json}}": constraints, "{{evidence_json}}": evidence}
	for k, v := range replacements {
		user = strings.ReplaceAll(user, k, v)
	}
	if len(user) > t.MaxInputChars {
		return Rendered{}, fmt.Errorf("rendered prompt exceeds max_input_chars")
	}
	messages := []provider.Message{{Role: "system", Content: t.System}, {Role: "developer", Content: t.Developer}, {Role: "user", Content: user}}
	b, _ := json.Marshal(messages)
	sum := sha256.Sum256(b)
	return Rendered{Messages: messages, InputDigest: hex.EncodeToString(sum[:])}, nil
}

func renderEvidence(items []llm.Evidence) string {
	var b strings.Builder
	for _, ev := range items {
		fmt.Fprintf(&b, "<untrusted_evidence id=%q kind=%q path=%q>\n%s\n</untrusted_evidence>\n", ev.ID, ev.Kind, ev.Path, ev.Text)
	}
	return b.String()
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
