package fake

import (
	"context"
	adapterscm "github.com/Ozark-Security-Labs/Tallow/internal/adapters/scm"
)

type Adapter struct{}

var _ adapterscm.Adapter = (*Adapter)(nil)

func (Adapter) Provider() adapterscm.Provider { return adapterscm.ProviderGitHub }
func (Adapter) NormalizeRepository(raw string) (adapterscm.RepositoryIdentity, error) {
	return adapterscm.RepositoryIdentity{Provider: adapterscm.ProviderGitHub, Owner: "owner", Name: "repo", URL: raw}, nil
}
func (Adapter) FetchRepository(context.Context, adapterscm.RepositoryIdentity) (adapterscm.RepositoryMetadata, error) {
	return adapterscm.RepositoryMetadata{DefaultBranch: "main", Visibility: "public", RawMetadataDigest: "sha256:fake"}, nil
}
func (Adapter) FetchRevision(context.Context, adapterscm.RepositoryIdentity, string) (adapterscm.RevisionMetadata, error) {
	return adapterscm.RevisionMetadata{Revision: "abc123", Kind: "commit"}, nil
}
func (Adapter) FetchSourceEvidence(context.Context, adapterscm.RepositoryIdentity, string, string, int64) (adapterscm.SourceEvidence, error) {
	return adapterscm.SourceEvidence{Path: "package.json", Revision: "abc123", Digest: "sha256:fake", SizeBytes: 2}, nil
}
