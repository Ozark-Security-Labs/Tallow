package scm

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("scm adapter not implemented")

type Adapter interface {
	Provider() Provider
	NormalizeRepository(string) (RepositoryIdentity, error)
	FetchRepository(context.Context, RepositoryIdentity) (RepositoryMetadata, error)
	FetchRevision(context.Context, RepositoryIdentity, string) (RevisionMetadata, error)
	FetchSourceEvidence(context.Context, RepositoryIdentity, string, string, int64) (SourceEvidence, error)
}
