package notifications

import (
	"regexp"
	"strings"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(token|secret|password|webhook_url)=([^\s&]+)`),
	regexp.MustCompile(`(?i)("(?:token|secret|password|webhook_url)"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`https://[^\s]+/webhook/[^\s]+`),
}

func Redact(value string) string {
	out := value
	for _, pattern := range secretPatterns {
		out = pattern.ReplaceAllStringFunc(out, func(match string) string {
			if strings.Contains(match, `"`) && strings.Contains(match, `:`) {
				return pattern.ReplaceAllString(match, `$1[redacted]$3`)
			}
			if strings.Contains(match, "/webhook/") {
				return "https://[redacted]/webhook/[redacted]"
			}
			return pattern.ReplaceAllString(match, `$1=[redacted]`)
		})
	}
	if strings.Contains(strings.ToLower(out), "authorization: bearer ") {
		out = regexp.MustCompile(`(?i)authorization: bearer\s+\S+`).ReplaceAllString(out, "Authorization: Bearer [redacted]")
	}
	return out
}
