package snapshot

import (
	"bytes"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/unpack"
)

func TestWriteDeterministicSnapshot(t *testing.T) {
	lc := 1
	in := Input{ID: "snap-1", ArtifactID: "artifact-1", ArtifactKind: "npm_tarball", Package: PackageRef{Ecosystem: "npm", Name: "pkg", Registry: "https://registry.npmjs.org"}, Version: "1.0.0", ManifestURI: "fs://artifacts/manifests/artifact-1.json", Metadata: map[string]string{"source": "fixture"}, Manifest: unpack.Manifest{Entries: []unpack.Entry{{Path: "b.js", Type: "file", Size: 1, Mode: 420, SHA256: "b", LineCount: &lc}, {Path: "a.js", Type: "file", Size: 1, Mode: 420, SHA256: "a", LineCount: &lc}}}, EvidenceRefs: []string{"evidence:b", "evidence:a"}}
	first, err := Write(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Write(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("snapshot output not deterministic")
	}
	if !bytes.Contains(first, []byte(`"file_inventory_digest"`)) || !bytes.Contains(first, []byte(`"manifest_uri"`)) || bytes.Index(first, []byte("a.js")) > bytes.Index(first, []byte("b.js")) {
		t.Fatalf("unexpected snapshot %s", first)
	}
}
