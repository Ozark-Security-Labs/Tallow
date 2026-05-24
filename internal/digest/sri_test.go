package digest

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseSRIAndPreferStrongest(t *testing.T) {
	sha256b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	sha512b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 64)))
	got, err := PreferredSRI("sha256-" + sha256b64 + " sha512-" + sha512b64)
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != AlgorithmSHA512 || got.Hex != strings.Repeat("62", 64) || got.Source != "sri" {
		t.Fatalf("unexpected preferred SRI %#v", got)
	}
}

func TestParseSRIRejectsUnsupportedAndMalformed(t *testing.T) {
	if _, err := ParseSRI("md5-abcd"); err == nil {
		t.Fatal("want unsupported algorithm")
	}
	if _, err := ParseSRI("sha256-not-base64!!"); err == nil {
		t.Fatal("want malformed base64")
	}
}
