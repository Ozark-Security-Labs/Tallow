package graph

import "testing"

func TestPropagateFindingIdentifiesDependentsAndPreservesImpact(t *testing.T) {
	target, mid, app := pv("bad"), pv("mid"), pv("app")
	impacts, err := PropagateFinding([]DependencyEdge{edge(mid, target), edge(app, mid)}, target, "finding-1", StatusCompromisedIntrinsic, TraverseOptions{MaxDepth: 3, MaxPathsPerRoot: 10}, Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(impacts) != 2 {
		t.Fatalf("expected direct and transitive dependents, got %d", len(impacts))
	}
	if impacts[0].Status != "affected_by_transitive" || impacts[0].SourceFindingID != "finding-1" || impacts[0].PathFingerprint == "" {
		t.Fatalf("impact evidence not preserved: %+v", impacts[0])
	}
	if impacts[1].Depth != 2 {
		t.Fatalf("expected transitive depth 2, got %+v", impacts[1])
	}
}

func TestPropagateFindingPaginatesDeterministically(t *testing.T) {
	target, a, b := pv("bad"), pv("a"), pv("b")
	first, err := PropagateFinding([]DependencyEdge{edge(b, target), edge(a, target)}, target, "finding-1", StatusSuspicious, TraverseOptions{MaxDepth: 2, MaxPathsPerRoot: 10}, Page{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := PropagateFinding([]DependencyEdge{edge(b, target), edge(a, target)}, target, "finding-1", StatusSuspicious, TraverseOptions{MaxDepth: 2, MaxPathsPerRoot: 10}, Page{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Root.NormalizedName != "a" || second[0].Root.NormalizedName != "b" {
		t.Fatalf("pagination not deterministic: %+v %+v", first, second)
	}
}
