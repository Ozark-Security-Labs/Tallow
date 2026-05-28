package redaction

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

type Options struct {
	MaxBytes     int
	RedactEmails bool
}
type Finding struct {
	Type  string
	Count int
}
type Result struct {
	Text          string
	Findings      []Finding
	Truncated     bool
	OriginalBytes int
	RedactedBytes int
}
type EvidenceSnippet struct {
	ID, Kind, Path, Text string
	Redacted             bool
}
type Redactor interface {
	RedactText(string, Options) Result
	RedactEvidence(EvidenceSnippet, Options) EvidenceSnippet
}

type DefaultRedactor struct{}

var patterns = []struct {
	typ, repl string
	re        *regexp.Regexp
}{
	{"aws_access_key_id", "[REDACTED:AWS_ACCESS_KEY_ID]", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"github_token", "[REDACTED:GITHUB_TOKEN]", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`)},
	{"bearer_token", "[REDACTED:TOKEN]", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{12,}`)},
	{"api_token", "[REDACTED:TOKEN]", regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9._\-/+=]{12,}`)},
	{"url_credential", "[REDACTED:URL_CREDENTIAL]", regexp.MustCompile(`https?://[^\s/@]+:[^\s/@]+@[^\s]+`)},
	{"local_path", "[REDACTED:LOCAL_PATH]", regexp.MustCompile(`(/home|/Users|/workspace|/tmp)/[A-Za-z0-9._/@+\-]+`)},
}
var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

func (DefaultRedactor) RedactText(input string, opts Options) Result {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 4096
	}
	if !opts.RedactEmails {
		opts.RedactEmails = true
	}
	text := input
	counts := map[string]int{}
	for _, p := range patterns {
		matches := p.re.FindAllStringIndex(text, -1)
		if len(matches) > 0 {
			counts[p.typ] += len(matches)
			text = p.re.ReplaceAllString(text, p.repl)
		}
	}
	if opts.RedactEmails {
		matches := emailRe.FindAllStringIndex(text, -1)
		if len(matches) > 0 {
			counts["email"] += len(matches)
			text = emailRe.ReplaceAllString(text, "[REDACTED:EMAIL]")
		}
	}
	truncated := false
	if len([]byte(text)) > opts.MaxBytes {
		original := len([]byte(text))
		text = truncateUTF8(text, opts.MaxBytes)
		removed := original - len([]byte(text))
		text += "[TRUNCATED:" + itoa(removed) + "]"
		counts["oversized_blob"]++
		truncated = true
	}
	findings := make([]Finding, 0, len(counts))
	for typ, c := range counts {
		findings = append(findings, Finding{Type: typ, Count: c})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Type < findings[j].Type })
	return Result{Text: text, Findings: findings, Truncated: truncated, OriginalBytes: len([]byte(input)), RedactedBytes: len([]byte(text))}
}
func (r DefaultRedactor) RedactEvidence(in EvidenceSnippet, opts Options) EvidenceSnippet {
	res := r.RedactText(in.Text, opts)
	in.Text = res.Text
	in.Redacted = true
	return in
}
func truncateUTF8(s string, max int) string {
	b := []byte(s)
	if len(b) <= max {
		return s
	}
	b = b[:max]
	for !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
func ContainsSecretLike(s string) bool {
	for _, p := range patterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return emailRe.MatchString(s) || strings.Contains(s, "Ignore all previous instructions")
}
