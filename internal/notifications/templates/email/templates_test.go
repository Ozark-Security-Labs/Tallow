package email_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/notifications/templates"
)

func TestEmailTemplates(t *testing.T) {
	cases := []struct {
		name string
		data map[string]any
	}{
		{"high_risk_finding", map[string]any{"package_name": "left-pad", "version": "1.3.0", "ecosystem": "npm", "severity": "high", "confidence": "high", "rule_ids": "npm.lifecycle.install_script", "evidence_summary": "install script writes to temporary directory", "triage_url": "https://tallow.local/findings/fin-1?view=full", "review_action": "Review the package release evidence and decide whether to suppress or escalate."}},
		{"scan_failed", map[string]any{"package_name": "sample", "version": "2.0.0", "ecosystem": "pypi", "run_id": "run-1", "sanitized_error": "analyzer exited with code 2", "triage_url": "https://tallow.local/analyzer-runs/run-1?debug=true"}},
		{"digest", map[string]any{"digest_window": "24h", "finding_count": 3, "critical_count": 1, "high_count": 2, "package_summary": "npm/left-pad, pypi/sample", "triage_url": "https://tallow.local/findings?severity=high"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := loadTemplate(t, tc.name)
			rendered, err := templates.Render(tmpl, tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if rendered.Email == nil || rendered.Email.Text == "" || rendered.Email.HTML == "" {
				t.Fatalf("missing rendered email: %#v", rendered.Email)
			}
			assertGolden(t, tc.name+".golden.txt", rendered.Email.Text)
			assertGolden(t, tc.name+".golden.html", rendered.Email.HTML)
			if strings.Contains(strings.ToLower(rendered.Email.Text), "confirmed malware") || strings.Contains(rendered.Email.Text, "?view=full") || strings.Contains(rendered.Email.Text, "?debug=true") {
				t.Fatalf("unsafe or overclaiming text: %s", rendered.Email.Text)
			}
		})
	}
}

func loadTemplate(t *testing.T, name string) templates.Template {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "email", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var tmpl templates.Template
	if err := json.Unmarshal(b, &tmpl); err != nil {
		t.Fatal(err)
	}
	return tmpl
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(got) {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\ngot:\n%s", name, want, got)
	}
}
