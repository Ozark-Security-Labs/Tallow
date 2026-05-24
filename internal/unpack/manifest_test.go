package unpack

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestGoldenDeterministic(t *testing.T) {
	data := buildTar(t,
		&tar.Header{Name: "b.txt", Mode: 0o644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"body": "b\n"}},
		&tar.Header{Name: "a.txt", Mode: 0o644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"body": "a\n"}},
	)
	m, err := ReadTar("artifact-golden", bytes.NewReader(data), Policy{MaxFiles: 10, MaxFileBytes: 100, MaxTotalBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.JSON()
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("..", "..", "testdata", "snapshots", "unpack-manifest.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(append(got, '\n')) != string(want) {
		t.Fatalf("manifest golden mismatch\n got: %s\nwant: %s", got, want)
	}
}
