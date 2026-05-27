package mock

import (
	"context"

	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
)

type Adapter struct {
	Repositories map[string]scm.Repository
	Manifests    map[string]scm.Manifest
	Revisions    map[string]scm.Revision
	Page         scm.RepositoryPage
}

func (a Adapter) ResolveRepository(_ context.Context, ref scm.RepositoryRef) (scm.Repository, error) {
	if r, ok := a.Repositories[ref.URL]; ok {
		return r, nil
	}
	return scm.Repository{}, scm.ErrNotFound
}
func (a Adapter) FetchManifest(_ context.Context, ref scm.RepositoryRef, path, revision string) (scm.Manifest, error) {
	if m, ok := a.Manifests[ref.URL+":"+revision+":"+path]; ok {
		return m, nil
	}
	return scm.Manifest{}, scm.ErrNotFound
}
func (a Adapter) RevisionMetadata(_ context.Context, ref scm.RepositoryRef, revision string) (scm.Revision, error) {
	if r, ok := a.Revisions[ref.URL+":"+revision]; ok {
		return r, nil
	}
	return scm.Revision{}, scm.ErrNotFound
}
func (a Adapter) PollRepositories(context.Context, scm.RepositoryCursor) (scm.RepositoryPage, error) {
	return a.Page, nil
}
