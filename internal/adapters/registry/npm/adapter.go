package npm

import (
	"context"
	reg "github.com/Ozark-Security-Labs/Tallow/internal/adapters/registry"
	"github.com/Ozark-Security-Labs/Tallow/internal/identity"
)

type Adapter struct{ RegistryURL string }

var _ reg.Adapter = (*Adapter)(nil)

func (Adapter) Ecosystem() reg.Ecosystem { return reg.EcosystemNPM }
func (a Adapter) CanonicalPackageName(raw string) (reg.PackageIdentity, error) {
	parts, err := identity.NormalizePackageName(identity.EcosystemNPM, raw)
	if err != nil {
		return reg.PackageIdentity{}, err
	}
	url := a.RegistryURL
	if url == "" {
		url = "https://registry.npmjs.org"
	}
	return reg.PackageIdentity{Ecosystem: reg.EcosystemNPM, RawName: raw, NormalizedName: parts.NormalizedName, Namespace: parts.Namespace, RegistryURL: url}, nil
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
