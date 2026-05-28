package graph

import "time"

type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPyPI Ecosystem = "pypi"
)

type Scope string

const (
	ScopeRuntime  Scope = "runtime"
	ScopeDev      Scope = "dev"
	ScopeOptional Scope = "optional"
	ScopePeer     Scope = "peer"
	ScopeBuild    Scope = "build"
	ScopeTest     Scope = "test"
	ScopeUnknown  Scope = "unknown"
)

type Relationship string

const (
	RelationshipDirect     Relationship = "direct"
	RelationshipTransitive Relationship = "transitive"
)

type Confidence string

const (
	ConfidenceResolvedLockfile Confidence = "resolved_lockfile"
	ConfidenceDeclaredMetadata Confidence = "declared_metadata"
	ConfidenceInferred         Confidence = "inferred"
)

type SourceType string

const (
	SourceLockfile         SourceType = "lockfile"
	SourceManifest         SourceType = "manifest"
	SourceSBOM             SourceType = "sbom"
	SourceRegistryMetadata SourceType = "registry_metadata"
	SourceManual           SourceType = "manual"
)

type PackageVersion struct {
	ID                string
	Ecosystem         Ecosystem
	Name              string
	NormalizedName    string
	Version           string
	NormalizedVersion string
}

type EvidenceRef struct {
	Kind        string `json:"kind,omitempty"`
	ArtifactID  string `json:"artifact_id,omitempty"`
	Path        string `json:"path,omitempty"`
	Description string `json:"description,omitempty"`
}

type DependencyEdge struct {
	ID                     string
	Parent                 PackageVersion
	ChildPackageID         string
	ChildEcosystem         Ecosystem
	ChildName              string
	ChildNormalizedName    string
	ChildVersion           string
	ChildNormalizedVersion string
	Constraint             string
	Scope                  Scope
	Relationship           Relationship
	Optional               bool
	Dev                    bool
	Build                  bool
	Confidence             Confidence
	SourceType             SourceType
	ManifestPath           string
	LockfilePath           string
	DependencyPath         []PackageVersion
	Evidence               []EvidenceRef
	ObservedAt             time.Time
	Fingerprint            string
}

type IngestionRun struct {
	ID               string
	SourceKind       string
	SourceID         string
	ArtifactID       string
	PackageVersionID string
	InputFingerprint string
	StartedAt        time.Time
	FinishedAt       time.Time
	EdgesObserved    int
}

type DependencyObservation struct {
	Parent       PackageVersion
	ChildName    string
	ChildVersion string
	Constraint   string
	Scope        Scope
	Relationship Relationship
	Optional     bool
	Dev          bool
	Build        bool
	Confidence   Confidence
	SourceType   SourceType
	ManifestPath string
	LockfilePath string
	Path         []PackageVersion
	Evidence     []EvidenceRef
}
