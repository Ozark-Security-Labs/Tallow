package identity

import (
	"testing"
	"time"
)

func TestNormalizePackageName(t *testing.T) {
	cases := []struct {
		eco                 Ecosystem
		raw, norm, ns, name string
		ok                  bool
	}{{EcosystemNPM, "@Scope/Name", "@scope/name", "scope", "name", true}, {EcosystemNPM, "Left_Pad", "left_pad", "", "left_pad", true}, {EcosystemPyPI, "My_Pkg.Name", "my-pkg-name", "", "my-pkg-name", true}, {EcosystemPyPI, "bad/name", "", "", "", false}, {EcosystemNPM, "@bad//x", "", "", "", false}, {EcosystemNPM, "unicodé", "", "", "", false}, {EcosystemPyPI, "a..b", "", "", "", false}, {EcosystemPyPI, "a_b.c-d", "a-b-c-d", "", "a-b-c-d", true}, {EcosystemNPM, "a b", "", "", "", false}, {EcosystemNPM, "a\\b", "", "", "", false}, {EcosystemPyPI, "Requests", "requests", "", "requests", true}, {EcosystemPyPI, "zope.interface", "zope-interface", "", "zope-interface", true}, {EcosystemNPM, "@a/b", "@a/b", "a", "b", true}, {EcosystemNPM, "@a/", "", "", "", false}, {EcosystemPyPI, "___", "-", "", "-", true}, {EcosystemNPM, "pkg+tag", "pkg+tag", "", "pkg+tag", true}, {EcosystemPyPI, "typo-squat", "typo-squat", "", "typo-squat", true}, {EcosystemNPM, "@types/node", "@types/node", "types", "node", true}, {EcosystemNPM, "../x", "", "", "", false}, {EcosystemPyPI, "", "", "", "", false}}
	for _, c := range cases {
		got, err := NormalizePackageName(c.eco, c.raw)
		if c.ok && err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("%s expected err", c.raw)
		}
		if c.ok && (got.NormalizedName != c.norm || got.Namespace != c.ns || got.Name != c.name) {
			t.Fatalf("%s got %#v", c.raw, got)
		}
	}
}
func TestPackageValidate(t *testing.T) {
	p := PackageIdentity{Ecosystem: EcosystemNPM, RawName: "@S/N", NormalizedName: "@s/n", Namespace: "s", Name: "n", RegistryURL: "https://registry.npmjs.org"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Ecosystem = "gem"
	if err := p.Validate(); err == nil {
		t.Fatal("want err")
	}
}
func TestVersion(t *testing.T) {
	if NormalizeVersion(EcosystemNPM, "1.2.3-beta+Build").RawVersion == "" {
		t.Fatal()
	}
	if NormalizeVersion(EcosystemPyPI, "1.0+local").NormalizationStatus != StatusWarning {
		t.Fatal("want warning")
	}
	if NormalizeVersion(EcosystemNPM, "bad/version").NormalizationStatus != StatusRejected {
		t.Fatal("want rejected")
	}
}
func TestArtifact(t *testing.T) {
	a := ArtifactIdentity{Kind: ArtifactPyPIWheel, Filename: "pkg-1-py3-none-any.whl", DownloadURL: "https://files.pythonhosted.org/pkg.whl", Digests: map[string]string{"sha256": "abcdef"}, ObservedAt: time.Now()}
	b := a
	b.Filename = "pkg-1-cp312-linux.whl"
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if a.PreDownloadKey() == b.PreDownloadKey() {
		t.Fatal("wheel variants collide")
	}
}
