package sqlc

import (
	"strings"
	"testing"
)

func TestUpsertFindingPreservesReviewerStatus(t *testing.T) {
	if strings.Contains(upsertFinding, "status = EXCLUDED.status") {
		t.Fatal("upsertFinding must preserve existing reviewer status on replay")
	}
	if !strings.Contains(upsertFinding, "RETURNING id") || !strings.Contains(upsertFinding, "status") {
		t.Fatal("upsertFinding must return persisted status")
	}
}

func TestListFindingsIncludesAcceptanceFilters(t *testing.T) {
	for _, fragment := range []string{
		"ecosystem = $1",
		"package_name = $2",
		"version = $3",
		"severity_hint = $4",
		"confidence = $5",
		"category = $6",
		"rule_id = $7",
		"status = $8",
		"artifact_id = $9",
		"snapshot_id = $10",
		"created_at >= $11",
		"created_at <= $12",
		"created_at < $13",
		"ORDER BY created_at DESC, id DESC",
	} {
		if !strings.Contains(listFindings, fragment) {
			t.Fatalf("listFindings missing %q", fragment)
		}
	}
}
