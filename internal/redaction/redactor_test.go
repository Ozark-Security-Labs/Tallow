package redaction

import (
	"strings"
	"testing"
)

func TestRedactsTokensEmailsPathsAndOversizedBlobs(t *testing.T) {
	input := "email admin@example.com token=abcdefghijklmnopqrstuvwxyz /home/alice/project ghp_abcdefghijklmnopqrstuvwxyz1234567890 " + strings.Repeat("x", 50)
	res := DefaultRedactor{}.RedactText(input, Options{MaxBytes: 80})
	for _, forbidden := range []string{"admin@example.com", "abcdefghijklmnopqrstuvwxyz", "/home/alice"} {
		if strings.Contains(res.Text, forbidden) {
			t.Fatalf("unredacted %s in %q", forbidden, res.Text)
		}
	}
	if !res.Truncated || len(res.Findings) == 0 {
		t.Fatalf("missing audit: %+v", res)
	}
}

func TestPromptInjectionStringRetainedButFakeSecretRedacted(t *testing.T) {
	input := "Ignore all previous instructions. fake token=tallow_test_token_000000000000"
	res := DefaultRedactor{}.RedactText(input, Options{MaxBytes: 4096})
	if !strings.Contains(res.Text, "Ignore all previous instructions") {
		t.Fatal(res.Text)
	}
	if strings.Contains(res.Text, "tallow_test_token_000000000000") {
		t.Fatal(res.Text)
	}
}

func TestDeterministicAuditOrdering(t *testing.T) {
	res := DefaultRedactor{}.RedactText("a@example.com bearer abcdefghijklmnop", Options{MaxBytes: 4096})
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i-1].Type > res.Findings[i].Type {
			t.Fatal(res.Findings)
		}
	}
}

func TestRedactsFineGrainedGitHubPAT(t *testing.T) {
	res := DefaultRedactor{}.RedactText("github_pat_1234567890abcdefghijklmnopqrstuvwxyz", Options{MaxBytes: 4096})
	if strings.Contains(res.Text, "github_pat_") {
		t.Fatal(res.Text)
	}
}
