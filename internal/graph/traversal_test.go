package graph

import "testing"

func pv(name string) PackageVersion {
	return PackageVersion{Ecosystem: EcosystemNPM, Name: name, NormalizedName: name, Version: "1.0.0", NormalizedVersion: "1.0.0"}
}
func edge(parent, child PackageVersion) DependencyEdge {
	return DependencyEdge{Parent: parent, ChildEcosystem: child.Ecosystem, ChildName: child.Name, ChildNormalizedName: child.NormalizedName, ChildVersion: child.Version, ChildNormalizedVersion: child.NormalizedVersion, Scope: ScopeRuntime, Relationship: RelationshipDirect, Confidence: ConfidenceResolvedLockfile, SourceType: SourceLockfile, LockfilePath: "package-lock.json"}
}

func TestTraverseDependentsHandlesDirectTransitiveDiamondAndCycle(t *testing.T) {
	target, left, right, app := pv("bad"), pv("left"), pv("right"), pv("app")
	edges := []DependencyEdge{edge(left, target), edge(right, target), edge(app, left), edge(app, right), edge(target, app)}
	paths, err := TraverseDependents(edges, target, TraverseOptions{MaxDepth: 4, MaxPathsPerRoot: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 {
		t.Fatalf("expected 4 paths through diamond with cycle suppressed, got %d: %+v", len(paths), paths)
	}
	if paths[0].Depth != 1 || paths[3].Depth != 2 {
		t.Fatalf("paths not ordered by depth: %+v", paths)
	}
	for _, p := range paths {
		if p.Root.NormalizedName == "bad" {
			t.Fatalf("cycle returned target as dependent: %+v", p)
		}
	}
}

func TestTraverseDependentsHonorsLimits(t *testing.T) {
	target, mid, app := pv("bad"), pv("mid"), pv("app")
	paths, err := TraverseDependents([]DependencyEdge{edge(mid, target), edge(app, mid)}, target, TraverseOptions{MaxDepth: 1, MaxPathsPerRoot: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0].Root.NormalizedName != "mid" {
		t.Fatalf("expected only direct path, got %+v", paths)
	}
}

func TestTraverseDependentsFiltersDevAndOptional(t *testing.T) {
	target, dev, optional, runtime := pv("bad"), pv("dev"), pv("optional"), pv("runtime")
	devEdge := edge(dev, target)
	devEdge.Dev = true
	devEdge.Scope = ScopeDev
	optionalEdge := edge(optional, target)
	optionalEdge.Optional = true
	optionalEdge.Scope = ScopeOptional
	paths, err := TraverseDependents([]DependencyEdge{devEdge, optionalEdge, edge(runtime, target)}, target, TraverseOptions{MaxDepth: 2, MaxPathsPerRoot: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0].Root.NormalizedName != "runtime" {
		t.Fatalf("expected only runtime path, got %+v", paths)
	}
	paths, err = TraverseDependents([]DependencyEdge{devEdge, optionalEdge, edge(runtime, target)}, target, TraverseOptions{MaxDepth: 2, MaxPathsPerRoot: 10, IncludeDev: true, IncludeOptional: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected all paths with filters enabled, got %+v", paths)
	}
}
