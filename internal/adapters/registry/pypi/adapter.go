package pypi

import (
	"context"
	reg "github.com/Ozark-Security-Labs/Tallow/internal/adapters/registry"
	"github.com/Ozark-Security-Labs/Tallow/internal/identity"
)

type Adapter struct{ RegistryURL string }

var _ reg.Adapter = (*Adapter)(nil)

func (Adapter) Ecosystem() reg.Ecosystem { return reg.EcosystemPyPI }
func (a Adapter) CanonicalPackageName(raw string) (reg.PackageIdentity, error) {
	parts, err := identity.NormalizePackageName(identity.EcosystemPyPI, raw)
	if err != nil {
		return reg.PackageIdentity{}, err
	}
	url := a.RegistryURL
	if url == "" {
		url = "https://pypi.org"
	}
	return reg.PackageIdentity{Ecosystem: reg.EcosystemPyPI, RawName: raw, NormalizedName: parts.NormalizedName, RegistryURL: url}, nil
}
func (Adapter) FetchPackage(context.Context, string) (reg.PackageMetadata, error) {
	return reg.PackageMetadata{}, reg.ErrNotImplemented
}
func (Adapter) FetchVersion(context.Context, string, string) (reg.VersionMetadata, error) {
	return reg.VersionMetadata{}, reg.ErrNotImplemented
}
func (Adapter) ListArtifacts(context.Context, string, string) ([]reg.ArtifactMetadata, error) {
	return nil, reg.ErrNotImplemented
}
