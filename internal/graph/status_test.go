package graph

import "testing"

func TestTransitiveImpactDoesNotMutateIntrinsicStatus(t *testing.T) {
	target, direct := pv("bad"), pv("direct")
	impacts, err := PropagateFinding([]DependencyEdge{edge(direct, target)}, target, "finding-1", StatusCompromisedIntrinsic, TraverseOptions{MaxDepth: 2, MaxPathsPerRoot: 10}, Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	intrinsic := map[string]IntrinsicStatus{versionKey(target.Ecosystem, target.NormalizedName, target.NormalizedVersion): StatusCompromisedIntrinsic}
	if _, ok := intrinsic[versionKey(direct.Ecosystem, direct.NormalizedName, direct.NormalizedVersion)]; ok {
		t.Fatal("direct dependent was marked intrinsically malicious")
	}
	if impacts[0].Status != "affected_by_transitive" {
		t.Fatalf("wrong derived status: %+v", impacts[0])
	}
}
