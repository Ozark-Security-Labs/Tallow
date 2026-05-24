package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/identity"
)

func TestStorageURIArtifactRawDeterministicAndSanitized(t *testing.T) {
	pkg := identity.PackageIdentity{Ecosystem: identity.EcosystemNPM, RawName: "@Scope/Name", NormalizedName: "@scope/name", Namespace: "scope", Name: "name", RegistryURL: "https://registry.npmjs.org"}
	ver := identity.NormalizeVersion(identity.EcosystemNPM, "1.0.0")
	art := identity.ArtifactIdentity{Kind: identity.ArtifactNPMTarball, Filename: "name-1.0.0.tgz", DownloadURL: "https://registry.npmjs.org/@scope/name/-/name-1.0.0.tgz", Digests: map[string]string{"sha256": strings.Repeat("a", 64)}, ObservedAt: time.Now()}
	got, err := ArtifactRawURI(pkg, ver, art, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	again, err := ArtifactRawURI(pkg, ver, art, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if got != again {
		t.Fatalf("not deterministic: %s != %s", got, again)
	}
	if strings.Contains(got, "@scope") || strings.Contains(got, "name-1.0.0") || !strings.HasPrefix(got, Prefix+"/raw/npm/") {
		t.Fatalf("URI leaks raw identity: %s", got)
	}
}

func TestStorageURIsDoNotCollideAcrossArtifactVariants(t *testing.T) {
	pkg := identity.PackageIdentity{Ecosystem: identity.EcosystemPyPI, RawName: "Pkg", NormalizedName: "pkg", Name: "pkg", RegistryURL: "https://pypi.org"}
	ver := identity.NormalizeVersion(identity.EcosystemPyPI, "1.0.0")
	base := identity.ArtifactIdentity{Filename: "pkg-1.0.0.tar.gz", DownloadURL: "https://files.pythonhosted.org/pkg.tar.gz", Digests: map[string]string{"sha256": strings.Repeat("b", 64)}, ObservedAt: time.Now()}
	base.Kind = identity.ArtifactPyPISDist
	sdist, err := ArtifactRawURI(pkg, ver, base, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	base.Kind = identity.ArtifactPyPIWheel
	base.Filename = "pkg-1.0.0-py3-none-any.whl"
	base.DownloadURL = "https://files.pythonhosted.org/pkg.whl"
	wheel, err := ArtifactRawURI(pkg, ver, base, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if sdist == wheel {
		t.Fatal("sdist and wheel URI collision")
	}
}

func TestStorageURIRejectsUnsafeInputs(t *testing.T) {
	for _, id := range []string{"", "../x", "/abs", "a/b", "a\\b", "a\nb", ".."} {
		if _, err := ManifestURI(id); err == nil {
			t.Fatalf("ManifestURI(%q) should reject", id)
		}
	}
	pkg := identity.PackageIdentity{Ecosystem: identity.EcosystemNPM, RawName: "pkg", NormalizedName: "pkg", Name: "pkg", RegistryURL: "https://registry.npmjs.org"}
	art := identity.ArtifactIdentity{Kind: identity.ArtifactNPMTarball, Filename: "../evil.tgz", DownloadURL: "https://registry.npmjs.org/pkg/-/pkg.tgz", Digests: map[string]string{"sha256": strings.Repeat("a", 64)}, ObservedAt: time.Now()}
	if _, err := ArtifactRawURI(pkg, identity.NormalizeVersion(identity.EcosystemNPM, "1"), art, strings.Repeat("a", 64)); err == nil {
		t.Fatal("unsafe filename should reject")
	}
	art.Filename = "pkg.tgz"
	if _, err := ArtifactRawURI(pkg, identity.NormalizeVersion(identity.EcosystemNPM, "1"), art, "nothex"); err == nil {
		t.Fatal("bad sha256 should reject")
	}
}

func TestDerivedURIs(t *testing.T) {
	m, err := ManifestURI("artifact-1")
	if err != nil || m != Prefix+"/manifests/artifact-1.json" {
		t.Fatalf("manifest %q %v", m, err)
	}
	s, err := SnapshotURI("artifact-1")
	if err != nil || s != Prefix+"/snapshots/artifact-1.json" {
		t.Fatalf("snapshot %q %v", s, err)
	}
	d, err := DiffURI("artifact-1", "artifact-2")
	if err != nil || d != Prefix+"/diffs/artifact-1/artifact-2.json" {
		t.Fatalf("diff %q %v", d, err)
	}
}
