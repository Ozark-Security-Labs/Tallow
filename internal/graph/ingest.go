package graph

import (
	"sort"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/identity"
	"sync"
	"time"
)

type Store interface {
	UpsertDependencyEdges([]DependencyEdge) ([]DependencyEdge, error)
	ListDependencyEdges() []DependencyEdge
}

type MemoryStore struct {
	mu    sync.Mutex
	edges map[string]DependencyEdge
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{edges: map[string]DependencyEdge{}} }

func (s *MemoryStore) UpsertDependencyEdges(edges []DependencyEdge) ([]DependencyEdge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DependencyEdge, 0, len(edges))
	for _, e := range edges {
		if e.ObservedAt.IsZero() {
			e.ObservedAt = time.Unix(0, 0).UTC()
		}
		if e.Fingerprint == "" {
			e.Fingerprint = EdgeFingerprint(e)
		}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		e.ID = e.Fingerprint
		s.edges[e.Fingerprint] = e
		out = append(out, e)
	}
	sortEdges(out)
	return out, nil
}
func (s *MemoryStore) ListDependencyEdges() []DependencyEdge {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DependencyEdge, 0, len(s.edges))
	for _, e := range s.edges {
		out = append(out, e)
	}
	sortEdges(out)
	return out
}

func IngestDependencies(store Store, observations []DependencyObservation) ([]DependencyEdge, error) {
	edges := make([]DependencyEdge, 0, len(observations))
	for _, o := range observations {
		childNorm := normalizeNameForEcosystem(o.Parent.Ecosystem, o.ChildName)
		childVer := strings.TrimSpace(o.ChildVersion)
		edges = append(edges, DependencyEdge{Parent: o.Parent, ChildEcosystem: o.Parent.Ecosystem, ChildName: o.ChildName, ChildNormalizedName: childNorm, ChildVersion: o.ChildVersion, ChildNormalizedVersion: childVer, Constraint: o.Constraint, Scope: o.Scope, Relationship: o.Relationship, Optional: o.Optional, Dev: o.Dev, Build: o.Build, Confidence: o.Confidence, SourceType: o.SourceType, ManifestPath: o.ManifestPath, LockfilePath: o.LockfilePath, DependencyPath: o.Path, Evidence: o.Evidence})
	}
	return store.UpsertDependencyEdges(edges)
}
func normalizeNameForEcosystem(ec Ecosystem, s string) string {
	parts, err := identity.NormalizePackageName(identity.Ecosystem(ec), s)
	if err == nil {
		return parts.NormalizedName
	}
	return strings.ToLower(strings.TrimSpace(s))
}
func sortEdges(edges []DependencyEdge) {
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		keysA := []string{string(a.Parent.Ecosystem), a.Parent.NormalizedName, a.Parent.NormalizedVersion, string(a.Relationship), a.ChildNormalizedName, a.ChildNormalizedVersion, a.Fingerprint}
		keysB := []string{string(b.Parent.Ecosystem), b.Parent.NormalizedName, b.Parent.NormalizedVersion, string(b.Relationship), b.ChildNormalizedName, b.ChildNormalizedVersion, b.Fingerprint}
		for k := range keysA {
			if keysA[k] != keysB[k] {
				return keysA[k] < keysB[k]
			}
		}
		return false
	})
}
