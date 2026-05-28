package registry

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("registry adapter not implemented")
var ErrUnsupportedEcosystem = errors.New("unsupported registry ecosystem")

type Adapter interface {
	Ecosystem() Ecosystem
	CanonicalPackageName(raw string) (PackageIdentity, error)
	FetchPackage(context.Context, string) (PackageMetadata, error)
	FetchVersion(context.Context, string, string) (VersionMetadata, error)
	ListArtifacts(context.Context, string, string) ([]ArtifactMetadata, error)
}
