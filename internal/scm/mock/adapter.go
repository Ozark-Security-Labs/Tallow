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

func (a Adapter) Provider() string { return "mock" }
func (a Adapter) ResolveRepository(_ context.Context, claim scm.RepositoryClaim) (scm.RepositoryRef, error) {
	if claim.URL != "" {
		return scm.RepositoryRef{Provider: claim.Provider, Owner: claim.Owner, Name: claim.Name, URL: claim.URL}, nil
	}
	return scm.RepositoryRef{}, scm.ErrNotFound
}
func (a Adapter) GetRepository(_ context.Context, ref scm.RepositoryRef) (scm.Repository, error) {
	if r, ok := a.Repositories[ref.URL]; ok {
		return r, nil
	}
	return scm.Repository{}, scm.ErrNotFound
}
func (a Adapter) GetDefaultBranch(_ context.Context, ref scm.RepositoryRef) (scm.Revision, error) {
	if r, ok := a.Repositories[ref.URL]; ok {
		return a.GetRevision(context.Background(), ref, r.DefaultBranch)
	}
	return scm.Revision{}, scm.ErrNotFound
}
func (a Adapter) ListRepositoryManifests(ctx context.Context, ref scm.RepositoryRef, revision string) ([]scm.Manifest, error) {
	out := []scm.Manifest{}
	for key, m := range a.Manifests {
		if len(key) >= len(ref.URL) && key[:len(ref.URL)] == ref.URL {
			out = append(out, m)
		}
	}
	return out, nil
}
func (a Adapter) FetchFile(_ context.Context, ref scm.RepositoryRef, path, revision string, maxBytes int64) (scm.Manifest, error) {
	if m, ok := a.Manifests[ref.URL+":"+revision+":"+path]; ok {
		if maxBytes > 0 && int64(len(m.Content)) > maxBytes {
			return scm.Manifest{}, scm.ErrInvalidResponse
		}
		return m, nil
	}
	return scm.Manifest{}, scm.ErrNotFound
}
func (a Adapter) FetchManifest(ctx context.Context, ref scm.RepositoryRef, path, revision string) (scm.Manifest, error) {
	return a.FetchFile(ctx, ref, path, revision, 1<<20)
}
func (a Adapter) GetRevision(_ context.Context, ref scm.RepositoryRef, revision string) (scm.Revision, error) {
	if r, ok := a.Revisions[ref.URL+":"+revision]; ok {
		return r, nil
	}
	return scm.Revision{}, scm.ErrNotFound
}
func (a Adapter) RevisionMetadata(ctx context.Context, ref scm.RepositoryRef, revision string) (scm.Revision, error) {
	return a.GetRevision(ctx, ref, revision)
}
func (a Adapter) Poll(context.Context, scm.RepositoryCursor) (scm.RepositoryPage, error) {
	return a.Page, nil
}
func (a Adapter) PollRepositories(ctx context.Context, cursor scm.RepositoryCursor) (scm.RepositoryPage, error) {
	return a.Poll(ctx, cursor)
}
