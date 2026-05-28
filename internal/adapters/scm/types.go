package scm

import "time"

type Provider string

const (
	ProviderGitHub     Provider = "github"
	ProviderGitLab     Provider = "gitlab"
	ProviderForgejo    Provider = "forgejo"
	ProviderGenericGit Provider = "generic_git"
)

type RepositoryIdentity struct {
	Provider Provider `json:"provider"`
	Owner    string   `json:"owner"`
	Name     string   `json:"name"`
	URL      string   `json:"url"`
}
type RepositoryMetadata struct {
	Identity          RepositoryIdentity `json:"identity"`
	DefaultBranch     string             `json:"default_branch"`
	Visibility        string             `json:"visibility"`
	RawMetadataDigest string             `json:"raw_metadata_digest"`
	ObservedAt        time.Time          `json:"observed_at"`
}
type SourceEvidence struct {
	Path      string `json:"path"`
	Revision  string `json:"revision"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"size_bytes"`
}
type RevisionMetadata struct {
	Revision   string           `json:"revision"`
	Kind       string           `json:"kind"`
	ObservedAt time.Time        `json:"observed_at"`
	Evidence   []SourceEvidence `json:"evidence"`
}
