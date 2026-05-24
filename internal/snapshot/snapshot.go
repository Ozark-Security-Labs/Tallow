package snapshot

import "github.com/Ozark-Security-Labs/Tallow/internal/unpack"

type Snapshot struct {
	ID                  string            `json:"id"`
	ArtifactID          string            `json:"artifact_id"`
	ArtifactKind        string            `json:"artifact_kind"`
	Package             PackageRef        `json:"package"`
	Version             string            `json:"version"`
	ManifestURI         string            `json:"manifest_uri"`
	Metadata            map[string]string `json:"metadata"`
	FileInventoryDigest string            `json:"file_inventory_digest"`
	Files               []unpack.Entry    `json:"files"`
	EvidenceRefs        []string          `json:"evidence_refs"`
}

type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Registry  string `json:"registry"`
}

type Input struct {
	ID           string
	ArtifactID   string
	ArtifactKind string
	Package      PackageRef
	Version      string
	ManifestURI  string
	Metadata     map[string]string
	Manifest     unpack.Manifest
	EvidenceRefs []string
}
