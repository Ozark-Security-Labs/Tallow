package graph

import (
	"os"
	"strings"
	"testing"
)

func TestDependencyEdgeSchemaFieldsAndConfidence(t *testing.T) {
	b, err := os.ReadFile("../../db/migrations/000004_dependency_graph.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(b)
	for _, fragment := range []string{
		"parent_package_version_id",
		"child_package_id",
		"constraint_text",
		"resolved_version",
		"scope TEXT",
		"is_optional BOOLEAN",
		"is_dev BOOLEAN",
		"is_build BOOLEAN",
		"resolved_lockfile",
		"declared_metadata",
		"inferred",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("schema missing %q", fragment)
		}
	}
}
