package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func EdgeFingerprint(e DependencyEdge) string {
	path := make([]string, 0, len(e.DependencyPath))
	for _, p := range e.DependencyPath {
		path = append(path, string(p.Ecosystem)+":"+p.NormalizedName+":"+p.NormalizedVersion)
	}
	payload := map[string]any{
		"parent":     string(e.Parent.Ecosystem) + ":" + e.Parent.NormalizedName + ":" + e.Parent.NormalizedVersion,
		"child":      string(e.ChildEcosystem) + ":" + e.ChildNormalizedName + ":" + e.ChildNormalizedVersion,
		"constraint": e.Constraint, "scope": e.Scope, "relationship": e.Relationship,
		"optional": e.Optional, "dev": e.Dev, "build": e.Build, "confidence": e.Confidence,
		"source_type": e.SourceType, "manifest_path": e.ManifestPath, "lockfile_path": e.LockfilePath,
		"path": strings.Join(path, ">"),
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
