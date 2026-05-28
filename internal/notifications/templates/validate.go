package templates

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
)

var variablePattern = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}`)

var forbiddenVariables = map[string]struct{}{
	"raw_artifact":          {},
	"raw_artifact_contents": {},
	"artifact_body":         {},
	"secret":                {},
	"token":                 {},
	"webhook_url":           {},
}

func Validate(t Template) error {
	if strings.TrimSpace(t.ID) == "" || strings.TrimSpace(t.Version) == "" {
		return fmt.Errorf("template id and version are required")
	}
	channels := map[Channel]bool{}
	for _, channel := range t.CompatibleChannels {
		channels[channel] = true
	}
	if len(channels) == 0 {
		return fmt.Errorf("template must declare compatible channels")
	}
	for name := range t.Variables {
		if _, forbidden := forbiddenVariables[strings.ToLower(name)]; forbidden || strings.Contains(strings.ToLower(name), "raw_artifact") {
			return fmt.Errorf("raw artifact or secret variable %q is not allowed", name)
		}
	}
	if channels[ChannelEmail] {
		if t.Targets.Email == nil || t.Targets.Email.Subject == "" || t.Targets.Email.Text == "" || t.Targets.Email.HTML == "" {
			return fmt.Errorf("email-compatible template requires subject, text, and html targets")
		}
	}
	if channels[ChannelTeams] {
		if t.Targets.Teams == nil || t.Targets.Teams.CardJSON == "" {
			return fmt.Errorf("teams-compatible template requires card_json target")
		}
	}
	for _, body := range targetBodies(t) {
		for _, name := range usedVariables(body) {
			if _, ok := t.Variables[name]; !ok {
				return fmt.Errorf("undeclared variable %q", name)
			}
		}
	}
	return nil
}

func Render(t Template, data map[string]any) (Rendered, error) {
	if err := Validate(t); err != nil {
		return Rendered{}, err
	}
	for name, variable := range t.Variables {
		if variable.Required {
			if _, ok := data[name]; !ok {
				return Rendered{}, fmt.Errorf("required variable %q missing", name)
			}
		}
	}
	redacted := map[string]string{}
	keys := make([]string, 0, len(t.Variables))
	for key := range t.Variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		redacted[key] = valueString(data[key], t.Variables[key].Redaction)
	}
	var rendered Rendered
	if t.Targets.Email != nil {
		rendered.Email = &RenderedEmail{
			Subject: renderString(t.Targets.Email.Subject, redacted, false),
			Text:    renderString(t.Targets.Email.Text, redacted, false),
			HTML:    renderString(t.Targets.Email.HTML, redacted, true),
		}
	}
	if t.Targets.Teams != nil {
		teams := renderString(t.Targets.Teams.CardJSON, redacted, false)
		var js any
		if err := json.Unmarshal([]byte(teams), &js); err != nil {
			return Rendered{}, fmt.Errorf("teams card_json is not valid json: %w", err)
		}
		canonical, _ := json.Marshal(js)
		rendered.Teams = &RenderedTeams{CardJSON: string(canonical)}
	}
	return rendered, nil
}

func targetBodies(t Template) []string {
	var bodies []string
	if t.Targets.Email != nil {
		bodies = append(bodies, t.Targets.Email.Subject, t.Targets.Email.Text, t.Targets.Email.HTML)
	}
	if t.Targets.Teams != nil {
		bodies = append(bodies, t.Targets.Teams.CardJSON)
	}
	return bodies
}

func usedVariables(body string) []string {
	matches := variablePattern.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, match[1])
	}
	return out
}

func renderString(body string, data map[string]string, escapeHTML bool) string {
	return variablePattern.ReplaceAllStringFunc(body, func(match string) string {
		parts := variablePattern.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		value := data[parts[1]]
		if escapeHTML {
			return html.EscapeString(value)
		}
		return value
	})
}

func valueString(value any, policy RedactionPolicy) string {
	if policy == RedactSecret {
		return "[redacted]"
	}
	text := fmt.Sprint(value)
	if policy == RedactURL {
		return redactURL(text)
	}
	return text
}

func redactURL(value string) string {
	if value == "" {
		return ""
	}
	if i := strings.Index(value, "://"); i >= 0 {
		prefix := value[:i+3]
		rest := value[i+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return prefix + rest[:slash] + "/..."
		}
	}
	return value
}
