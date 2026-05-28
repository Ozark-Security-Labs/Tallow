package prompt

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v2"
)

var allowedVariables = map[string]bool{"subject_json": true, "findings_json": true, "evidence_json": true, "constraints_json": true}
var placeholderRE = regexp.MustCompile(`\{\{([a-z_]+)\}\}`)

type Template struct {
	TemplateVersion string   `yaml:"template_version" json:"template_version"`
	System          string   `yaml:"system" json:"system"`
	Developer       string   `yaml:"developer" json:"developer"`
	UserTemplate    string   `yaml:"user_template" json:"user_template"`
	Variables       []string `yaml:"variables" json:"variables"`
	OutputSchemaRef string   `yaml:"output_schema_ref" json:"output_schema_ref"`
	MaxInputChars   int      `yaml:"max_input_chars" json:"max_input_chars"`
}

func Load(path string) (Template, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Template{}, err
	}
	var t Template
	if err := yaml.NewDecoder(bytes.NewReader(b)).Decode(&t); err != nil {
		return Template{}, err
	}
	return t, t.Validate()
}

func (t Template) Validate() error {
	if strings.TrimSpace(t.TemplateVersion) == "" {
		return fmt.Errorf("template_version required")
	}
	if !strings.Contains(strings.ToLower(t.System), "hostile") || !strings.Contains(strings.ToLower(t.System), "evidence") {
		return fmt.Errorf("system prompt must mark package contents as hostile evidence")
	}
	if t.OutputSchemaRef != "schemas/llm-narrative-output.schema.json" {
		return fmt.Errorf("unexpected output schema ref")
	}
	seen := map[string]bool{}
	for _, v := range t.Variables {
		if !allowedVariables[v] {
			return fmt.Errorf("unknown variable %q", v)
		}
		seen[v] = true
	}
	matches := placeholderRE.FindAllStringSubmatch(t.UserTemplate, -1)
	for _, m := range matches {
		if !allowedVariables[m[1]] {
			return fmt.Errorf("unknown placeholder %q", m[1])
		}
		if !seen[m[1]] {
			return fmt.Errorf("placeholder %q not declared", m[1])
		}
	}
	declared := make([]string, 0, len(seen))
	for v := range seen {
		declared = append(declared, v)
	}
	sort.Strings(declared)
	return nil
}
