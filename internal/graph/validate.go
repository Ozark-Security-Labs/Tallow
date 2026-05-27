package graph

import (
	"errors"
	"path/filepath"
	"strings"
)

func (v PackageVersion) Validate() error {
	if v.Ecosystem != EcosystemNPM && v.Ecosystem != EcosystemPyPI {
		return errors.New("unsupported ecosystem")
	}
	if v.NormalizedName == "" || v.Version == "" || v.NormalizedVersion == "" {
		return errors.New("package name and version required")
	}
	if unsafe(v.NormalizedName) || unsafe(v.Version) || unsafe(v.NormalizedVersion) {
		return errors.New("unsafe package version")
	}
	return nil
}

func (e DependencyEdge) Validate() error {
	if err := e.Parent.Validate(); err != nil {
		return err
	}
	if e.ChildEcosystem != EcosystemNPM && e.ChildEcosystem != EcosystemPyPI {
		return errors.New("unsupported child ecosystem")
	}
	if e.ChildNormalizedName == "" {
		return errors.New("child package required")
	}
	if unsafe(e.ChildNormalizedName) || unsafe(e.ChildVersion) || unsafe(e.Constraint) {
		return errors.New("unsafe dependency identity")
	}
	if !validScope(e.Scope) {
		return errors.New("invalid dependency scope")
	}
	if e.Relationship != RelationshipDirect && e.Relationship != RelationshipTransitive {
		return errors.New("invalid relationship")
	}
	if !validConfidence(e.Confidence) {
		return errors.New("invalid confidence")
	}
	if !validSource(e.SourceType) {
		return errors.New("invalid source type")
	}
	if unsafePath(e.ManifestPath) || unsafePath(e.LockfilePath) {
		return errors.New("unsafe evidence path")
	}
	return nil
}

func validScope(s Scope) bool {
	switch s {
	case ScopeRuntime, ScopeDev, ScopeOptional, ScopePeer, ScopeBuild, ScopeTest, ScopeUnknown:
		return true
	}
	return false
}
func validConfidence(c Confidence) bool {
	switch c {
	case ConfidenceResolvedLockfile, ConfidenceDeclaredMetadata, ConfidenceInferred:
		return true
	}
	return false
}
func validSource(s SourceType) bool {
	switch s {
	case SourceLockfile, SourceManifest, SourceSBOM, SourceRegistryMetadata, SourceManual:
		return true
	}
	return false
}
func unsafe(s string) bool {
	return strings.ContainsAny(s, "\\\x00\n\r\t") || strings.Contains(s, "..")
}
func unsafePath(s string) bool {
	return s != "" && (filepath.IsAbs(s) || strings.Contains(s, "\\") || strings.Contains(s, ".."))
}
