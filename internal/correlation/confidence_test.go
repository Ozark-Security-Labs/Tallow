package correlation

import (
	"os"
	"strings"
	"testing"
)

func TestSourceCorrelationConfidenceModelDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/architecture/source-correlation.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, fragment := range []string{"exact_metadata", "release_tag_match", "repository_metadata", "manifest_observed", "inferred_name", "conflicting", "unknown", "must not choose one repository and claim certainty", "exact/missing/multiple/conflicting"} {
		if !strings.Contains(doc, fragment) {
			t.Fatalf("source correlation docs missing %q", fragment)
		}
	}
}
