package graph

import "sort"

type IntrinsicStatus string

const (
	StatusClean                IntrinsicStatus = "clean"
	StatusSuspicious           IntrinsicStatus = "suspicious"
	StatusCompromisedIntrinsic IntrinsicStatus = "compromised_intrinsic"
	StatusUnknown              IntrinsicStatus = "unknown"
	StatusSuppressed           IntrinsicStatus = "suppressed"
)

type TransitiveImpact struct {
	Root            PackageVersion
	Target          PackageVersion
	SourceFindingID string
	SourceStatus    IntrinsicStatus
	Status          string
	Depth           int
	Path            []DependencyEdge
	PathFingerprint string
	Evidence        []EvidenceRef
}
type Page struct {
	Limit  int
	Offset int
}

func PropagateFinding(edges []DependencyEdge, target PackageVersion, findingID string, status IntrinsicStatus, opts TraverseOptions, page Page) ([]TransitiveImpact, error) {
	paths, err := TraverseDependents(edges, target, opts)
	if err != nil {
		return nil, err
	}
	impacts := make([]TransitiveImpact, 0, len(paths))
	for _, p := range paths {
		impacts = append(impacts, TransitiveImpact{Root: p.Root, Target: target, SourceFindingID: findingID, SourceStatus: status, Status: "affected_by_transitive", Depth: p.Depth, Path: p.Edges, PathFingerprint: p.Fingerprint})
	}
	sort.Slice(impacts, func(i, j int) bool {
		a, b := impacts[i], impacts[j]
		if a.Depth != b.Depth {
			return a.Depth < b.Depth
		}
		ak := versionKey(a.Root.Ecosystem, a.Root.NormalizedName, a.Root.NormalizedVersion) + a.PathFingerprint
		bk := versionKey(b.Root.Ecosystem, b.Root.NormalizedName, b.Root.NormalizedVersion) + b.PathFingerprint
		return ak < bk
	})
	if page.Offset < 0 {
		page.Offset = 0
	}
	if page.Limit <= 0 || page.Limit > len(impacts) {
		page.Limit = len(impacts)
	}
	if page.Offset >= len(impacts) {
		return []TransitiveImpact{}, nil
	}
	end := page.Offset + page.Limit
	if end > len(impacts) {
		end = len(impacts)
	}
	return impacts[page.Offset:end], nil
}
