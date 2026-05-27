package scm

import "context"

type RepositoryClaim struct {
	Provider string
	Owner    string
	Name     string
	URL      string
	Evidence string
}

type RepositoryCursor struct {
	Since     string
	PageToken string
}

type RepositoryPage struct {
	Repositories []RepositoryRef
	NextCursor   RepositoryCursor
}

type Adapter interface {
	Provider() string
	ResolveRepository(context.Context, RepositoryClaim) (RepositoryRef, error)
	GetRepository(context.Context, RepositoryRef) (Repository, error)
	GetDefaultBranch(context.Context, RepositoryRef) (Revision, error)
	ListRepositoryManifests(context.Context, RepositoryRef, string) ([]Manifest, error)
	FetchFile(context.Context, RepositoryRef, string, string, int64) (Manifest, error)
	GetRevision(context.Context, RepositoryRef, string) (Revision, error)
	Poll(context.Context, RepositoryCursor) (RepositoryPage, error)
}
