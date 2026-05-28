package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	reg "github.com/Ozark-Security-Labs/Tallow/internal/adapters/registry"
)

type Adapter struct{ EcosystemName reg.Ecosystem }

var _ reg.Adapter = (*Adapter)(nil)

func (a Adapter) Ecosystem() reg.Ecosystem {
	if a.EcosystemName != "" {
		return a.EcosystemName
	}
	return reg.EcosystemNPM
}
func (a Adapter) CanonicalPackageName(raw string) (reg.PackageIdentity, error) {
	return reg.PackageIdentity{Ecosystem: a.Ecosystem(), RawName: raw, NormalizedName: raw, RegistryURL: "https://registry.example.invalid"}, nil
}
func (a Adapter) FetchPackage(ctx context.Context, name string) (reg.PackageMetadata, error) {
	id, _ := a.CanonicalPackageName(name)
	sum := sha256.Sum256([]byte(name))
	return reg.PackageMetadata{Identity: id, LatestVersion: "1.0.0", RawMetadataDigest: hex.EncodeToString(sum[:])}, nil
}
func (a Adapter) FetchVersion(ctx context.Context, name, version string) (reg.VersionMetadata, error) {
	id, _ := a.CanonicalPackageName(name)
	return reg.VersionMetadata{Identity: id, Version: version, RawMetadataDigest: "sha256:fake"}, nil
}
func (a Adapter) ListArtifacts(ctx context.Context, name, version string) ([]reg.ArtifactMetadata, error) {
	return []reg.ArtifactMetadata{{Name: name + "-" + version + ".tgz", Kind: "archive", DownloadURL: "https://registry.example.invalid/artifact.tgz", RegistryHashes: map[string]string{"sha256": "00"}}}, nil
}
