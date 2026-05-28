package graph

import "testing"

func TestIngestDependenciesIdempotentAndScoped(t *testing.T) {
	store := NewMemoryStore()
	root := PackageVersion{Ecosystem: EcosystemNPM, Name: "app", NormalizedName: "app", Version: "1.0.0", NormalizedVersion: "1.0.0"}
	obs := []DependencyObservation{
		{Parent: root, ChildName: "left-pad", ChildVersion: "1.3.0", Constraint: "^1.3.0", Scope: ScopeRuntime, Relationship: RelationshipDirect, Confidence: ConfidenceResolvedLockfile, SourceType: SourceLockfile, LockfilePath: "package-lock.json"},
		{Parent: root, ChildName: "dev-tool", ChildVersion: "2.0.0", Constraint: "^2.0.0", Scope: ScopeDev, Relationship: RelationshipDirect, Dev: true, Confidence: ConfidenceDeclaredMetadata, SourceType: SourceManifest, ManifestPath: "package.json"},
		{Parent: root, ChildName: "optional-native", ChildVersion: "3.0.0", Constraint: "^3.0.0", Scope: ScopeOptional, Relationship: RelationshipDirect, Optional: true, Confidence: ConfidenceDeclaredMetadata, SourceType: SourceManifest, ManifestPath: "package.json"},
	}
	if _, err := IngestDependencies(store, obs); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestDependencies(store, obs); err != nil {
		t.Fatal(err)
	}
	edges := store.ListDependencyEdges()
	if got := len(edges); got != 3 {
		t.Fatalf("expected idempotent 3 edges, got %d", got)
	}
	seenDev, seenOptional := false, false
	for _, edge := range edges {
		if edge.Dev && edge.Scope == ScopeDev {
			seenDev = true
		}
		if edge.Optional && edge.Scope == ScopeOptional {
			seenOptional = true
		}
	}
	if !seenDev {
		t.Fatal("dev edge flags not preserved")
	}
	if !seenOptional {
		t.Fatal("optional edge flags not preserved")
	}
}

func TestIngestDependenciesUsesCanonicalPyPINormalization(t *testing.T) {
	store := NewMemoryStore()
	root := PackageVersion{Ecosystem: EcosystemPyPI, Name: "root", NormalizedName: "root", Version: "1.0.0", NormalizedVersion: "1.0.0"}
	if _, err := IngestDependencies(store, []DependencyObservation{{Parent: root, ChildName: "My_Pkg", ChildVersion: "1.0.0", Scope: ScopeRuntime, Relationship: RelationshipDirect, Confidence: ConfidenceDeclaredMetadata, SourceType: SourceRegistryMetadata}}); err != nil {
		t.Fatal(err)
	}
	edges := store.ListDependencyEdges()
	if edges[0].ChildNormalizedName != "my-pkg" {
		t.Fatalf("expected canonical pypi name my-pkg, got %q", edges[0].ChildNormalizedName)
	}
}
