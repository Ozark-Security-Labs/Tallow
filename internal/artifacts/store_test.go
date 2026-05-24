package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreWritesWithinRoot(t *testing.T) {
	root := t.TempDir()
	st := FileStore{Root: root}
	got, err := st.Write("fs://artifacts/raw/npm/aa/bb/cc", []byte("artifact"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 8 {
		t.Fatal(got)
	}
	if _, err := os.Stat(filepath.Join(root, "raw/npm/aa/bb/cc")); err != nil {
		t.Fatal(err)
	}
}
func TestFileStoreRejectsUnsafeURI(t *testing.T) {
	_, err := FileStore{Root: t.TempDir()}.Write("fs://artifacts/../escape", []byte("x"))
	if err == nil {
		t.Fatal("want rejection")
	}
}
