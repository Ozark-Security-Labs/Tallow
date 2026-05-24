package diff

import (
	"bytes"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/snapshot"
	"github.com/Ozark-Security-Labs/Tallow/internal/unpack"
)

func TestDiffDeterministicAddedRemovedModifiedMetadata(t *testing.T) {
	from := snapshot.Snapshot{ArtifactID: "a1", Metadata: map[string]string{"license": "MIT"}, Files: []unpack.Entry{{Path: "same.txt", Type: "file", Size: 1, SHA256: "1"}, {Path: "removed.bin", Type: "file", Size: 10, SHA256: "r"}, {Path: "changed.js", Type: "file", Size: 1, SHA256: "old"}}}
	to := snapshot.Snapshot{ArtifactID: "a2", Metadata: map[string]string{"license": "Apache-2.0"}, Files: []unpack.Entry{{Path: "same.txt", Type: "file", Size: 1, SHA256: "1"}, {Path: "added.bin", Type: "file", Size: 12, SHA256: "a"}, {Path: "changed.js", Type: "file", Size: 2, SHA256: "new"}}}
	d := Compare("diff-1", from, to)
	if len(d.Added) != 1 || len(d.Removed) != 1 || len(d.Modified) != 1 || len(d.MetadataDeltas) != 1 {
		t.Fatalf("bad diff %#v", d)
	}
	b1, _ := Write(d)
	b2, _ := Write(Compare("diff-1", from, to))
	if !bytes.Equal(b1, b2) {
		t.Fatal("diff not deterministic")
	}
	if !bytes.Contains(b1, []byte(`"sha256"`)) {
		t.Fatalf("binary summaries missing hash: %s", b1)
	}
}
