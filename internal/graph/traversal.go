package graph

import (
	"errors"
	"sort"
)

type TraverseOptions struct {
	MaxDepth        int
	MaxPathsPerRoot int
	IncludeDev      bool
	IncludeOptional bool
}
type ImpactPath struct {
	Root        PackageVersion
	Target      PackageVersion
	Depth       int
	Edges       []DependencyEdge
	Fingerprint string
}

func TraverseDependents(edges []DependencyEdge, target PackageVersion, opts TraverseOptions) ([]ImpactPath, error) {
	if opts.MaxDepth <= 0 {
		return nil, errors.New("max depth required")
	}
	if opts.MaxPathsPerRoot <= 0 {
		return nil, errors.New("max paths per root required")
	}
	byChild := map[string][]DependencyEdge{}
	for _, e := range edges {
		byChild[versionKey(e.ChildEcosystem, e.ChildNormalizedName, e.ChildNormalizedVersion)] = append(byChild[versionKey(e.ChildEcosystem, e.ChildNormalizedName, e.ChildNormalizedVersion)], e)
	}
	for k := range byChild {
		sortEdges(byChild[k])
	}
	type state struct {
		current PackageVersion
		path    []DependencyEdge
		seen    map[string]bool
	}
	queue := []state{{current: target, seen: map[string]bool{versionKey(target.Ecosystem, target.NormalizedName, target.NormalizedVersion): true}}}
	var out []ImpactPath
	perRoot := map[string]int{}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if len(s.path) >= opts.MaxDepth {
			continue
		}
		for _, edge := range byChild[versionKey(s.current.Ecosystem, s.current.NormalizedName, s.current.NormalizedVersion)] {
			if !opts.IncludeDev && (edge.Dev || edge.Scope == ScopeDev) {
				continue
			}
			if !opts.IncludeOptional && (edge.Optional || edge.Scope == ScopeOptional) {
				continue
			}
			parentKey := versionKey(edge.Parent.Ecosystem, edge.Parent.NormalizedName, edge.Parent.NormalizedVersion)
			if s.seen[parentKey] {
				continue
			}
			nextPath := append(append([]DependencyEdge{}, s.path...), edge)
			root := edge.Parent
			if perRoot[parentKey] < opts.MaxPathsPerRoot {
				perRoot[parentKey]++
				out = append(out, ImpactPath{Root: root, Target: target, Depth: len(nextPath), Edges: nextPath, Fingerprint: PathFingerprint(nextPath)})
			}
			nextSeen := map[string]bool{}
			for k, v := range s.seen {
				nextSeen[k] = v
			}
			nextSeen[parentKey] = true
			queue = append(queue, state{current: root, path: nextPath, seen: nextSeen})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Depth != b.Depth {
			return a.Depth < b.Depth
		}
		ak := versionKey(a.Root.Ecosystem, a.Root.NormalizedName, a.Root.NormalizedVersion) + a.Fingerprint
		bk := versionKey(b.Root.Ecosystem, b.Root.NormalizedName, b.Root.NormalizedVersion) + b.Fingerprint
		return ak < bk
	})
	return out, nil
}

func PathFingerprint(edges []DependencyEdge) string {
	combined := DependencyEdge{Parent: PackageVersion{Ecosystem: EcosystemNPM, NormalizedName: "path", Version: "0", NormalizedVersion: "0"}, ChildEcosystem: EcosystemNPM, ChildNormalizedName: "path", ChildNormalizedVersion: "0", Scope: ScopeUnknown, Relationship: RelationshipTransitive, Confidence: ConfidenceInferred, SourceType: SourceManual}
	for _, e := range edges {
		combined.DependencyPath = append(combined.DependencyPath, PackageVersion{Ecosystem: e.Parent.Ecosystem, NormalizedName: e.Parent.NormalizedName, NormalizedVersion: e.Parent.NormalizedVersion})
	}
	return EdgeFingerprint(combined)
}
func versionKey(ec Ecosystem, name, version string) string {
	return string(ec) + ":" + name + ":" + version
}
