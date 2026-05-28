package notifications

import (
	"strings"
	"testing"
)

func TestRedactCoversCommonSecretFormats(t *testing.T) {
	input := `token=abc "password":"secret" Authorization: Bearer abc https://example.test/webhook/team-secret`
	got := Redact(input)
	for _, secret := range []string{"abc", "secret", "team-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q was not redacted from %q", secret, got)
		}
	}
}
