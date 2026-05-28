package registry

import "time"

type Ecosystem string

const (
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPyPI   Ecosystem = "pypi"
	EcosystemGo     Ecosystem = "go"
	EcosystemCrates Ecosystem = "crates"
)

type PackageIdentity struct {
	Ecosystem      Ecosystem `json:"ecosystem"`
	RawName        string    `json:"raw_name"`
	NormalizedName string    `json:"normalized_name"`
	Namespace      string    `json:"namespace,omitempty"`
	RegistryURL    string    `json:"registry_url"`
}
type PackageMetadata struct {
	Identity          PackageIdentity `json:"identity"`
	LatestVersion     string          `json:"latest_version"`
	RawMetadataDigest string          `json:"raw_metadata_digest"`
	ObservedAt        time.Time       `json:"observed_at"`
}
type VersionMetadata struct {
	Identity          PackageIdentity `json:"identity"`
	Version           string          `json:"version"`
	PublishedAt       time.Time       `json:"published_at"`
	RawMetadataDigest string          `json:"raw_metadata_digest"`
}
type ArtifactMetadata struct {
	Name           string            `json:"name"`
	Kind           string            `json:"kind"`
	DownloadURL    string            `json:"download_url"`
	RegistryHashes map[string]string `json:"registry_hashes"`
	SizeBytes      int64             `json:"size_bytes"`
	PublishedAt    time.Time         `json:"published_at"`
}
