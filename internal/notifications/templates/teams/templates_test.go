package teams_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/notifications/templates"
)

func TestTeamsTemplates(t *testing.T) {
	cases := []string{"high_risk_finding", "scan_failed", "digest"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			tmpl := loadTemplate(t, name)
			rendered, err := templates.Render(tmpl, map[string]any{"package_name": "left-pad", "version": "1.3.0", "ecosystem": "npm", "severity": "high", "rule_ids": "npm.lifecycle.install_script", "evidence_url": "https://tallow.local/findings/fin-1?token=value"})
			if err != nil {
				t.Fatal(err)
			}
			if rendered.Teams == nil || rendered.Teams.CardJSON == "" {
				t.Fatalf("missing teams card: %#v", rendered.Teams)
			}
			var js any
			if err := json.Unmarshal([]byte(rendered.Teams.CardJSON), &js); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, name+".golden.json", rendered.Teams.CardJSON)
			body := strings.ToLower(rendered.Teams.CardJSON)
			for _, forbidden := range []string{"webhook", "oauth", "raw artifact", "token=value"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("teams card leaked forbidden content %q: %s", forbidden, rendered.Teams.CardJSON)
				}
			}
			for _, required := range []string{"left-pad", "1.3.0", "high", "npm.lifecycle.install_script", "https://tallow.local/..."} {
				if !strings.Contains(rendered.Teams.CardJSON, required) {
					t.Fatalf("teams card missing %q: %s", required, rendered.Teams.CardJSON)
				}
			}
		})
	}
}

func loadTemplate(t *testing.T, name string) templates.Template {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "teams", name+".yaml"))
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
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(got) {
		t.Fatalf("golden mismatch for %s\nwant:\n%s\ngot:\n%s", name, want, got)
	}
}
