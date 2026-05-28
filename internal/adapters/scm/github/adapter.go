package github

import (
	"context"
	adapterscm "github.com/Ozark-Security-Labs/Tallow/internal/adapters/scm"
	githubscm "github.com/Ozark-Security-Labs/Tallow/internal/scm/github"
)

type Adapter struct{}

var _ adapterscm.Adapter = (*Adapter)(nil)

func (Adapter) Provider() adapterscm.Provider { return adapterscm.ProviderGitHub }
func (Adapter) NormalizeRepository(raw string) (adapterscm.RepositoryIdentity, error) {
	ref, ok := githubscm.NormalizeRepositoryURL(raw)
	if !ok {
		return adapterscm.RepositoryIdentity{}, adapterscm.ErrNotImplemented
	}
	return adapterscm.RepositoryIdentity{Provider: adapterscm.ProviderGitHub, Owner: ref.Owner, Name: ref.Name, URL: ref.URL}, nil
}
func (Adapter) FetchRepository(context.Context, adapterscm.RepositoryIdentity) (adapterscm.RepositoryMetadata, error) {
	return adapterscm.RepositoryMetadata{}, adapterscm.ErrNotImplemented
}
func (Adapter) FetchRevision(context.Context, adapterscm.RepositoryIdentity, string) (adapterscm.RevisionMetadata, error) {
	return adapterscm.RevisionMetadata{}, adapterscm.ErrNotImplemented
}
func (Adapter) FetchSourceEvidence(context.Context, adapterscm.RepositoryIdentity, string, string, int64) (adapterscm.SourceEvidence, error) {
	return adapterscm.SourceEvidence{}, adapterscm.ErrNotImplemented
}
