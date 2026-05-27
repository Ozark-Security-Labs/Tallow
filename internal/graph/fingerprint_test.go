package graph

import "testing"

func TestEdgeFingerprintStableAndIgnoresObservedAt(t *testing.T) {
	root := PackageVersion{Ecosystem: EcosystemNPM, Name: "app", NormalizedName: "app", Version: "1", NormalizedVersion: "1"}
	e := DependencyEdge{Parent: root, ChildEcosystem: EcosystemNPM, ChildName: "dep", ChildNormalizedName: "dep", ChildVersion: "2", ChildNormalizedVersion: "2", Scope: ScopeRuntime, Relationship: RelationshipDirect, Confidence: ConfidenceResolvedLockfile, SourceType: SourceLockfile, LockfilePath: "package-lock.json"}
	if EdgeFingerprint(e) != EdgeFingerprint(e) {
		t.Fatal("fingerprint not stable")
	}
	e.Constraint = "^2"
	if EdgeFingerprint(e) == EdgeFingerprint(DependencyEdge{Parent: root, ChildEcosystem: EcosystemNPM, ChildName: "dep", ChildNormalizedName: "dep", ChildVersion: "2", ChildNormalizedVersion: "2", Scope: ScopeRuntime, Relationship: RelationshipDirect, Confidence: ConfidenceResolvedLockfile, SourceType: SourceLockfile, LockfilePath: "package-lock.json"}) {
		t.Fatal("fingerprint should include constraint")
	}
}
