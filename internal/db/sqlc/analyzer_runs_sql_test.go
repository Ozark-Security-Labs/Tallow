package sqlc

import (
	"strings"
	"testing"
)

func TestInsertAnalyzerRunReplayUpdatesMetadata(t *testing.T) {
	for _, fragment := range []string{
		"analyzer_id = EXCLUDED.analyzer_id",
		"analyzer_version = EXCLUDED.analyzer_version",
		"ruleset_version = EXCLUDED.ruleset_version",
		"started_at = EXCLUDED.started_at",
		"input_json = EXCLUDED.input_json",
	} {
		if !strings.Contains(insertAnalyzerRun, fragment) {
			t.Fatalf("insertAnalyzerRun missing %q", fragment)
		}
	}
}
