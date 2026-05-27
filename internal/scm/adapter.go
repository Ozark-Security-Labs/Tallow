package scm

import "context"

type RepositoryCursor struct {
	Since     string
	PageToken string
}
type RepositoryPage struct {
	Repositories []RepositoryRef
	NextCursor   RepositoryCursor
}

type Adapter interface {
	ResolveRepository(context.Context, RepositoryRef) (Repository, error)
	FetchManifest(context.Context, RepositoryRef, string, string) (Manifest, error)
	RevisionMetadata(context.Context, RepositoryRef, string) (Revision, error)
	PollRepositories(context.Context, RepositoryCursor) (RepositoryPage, error)
}
