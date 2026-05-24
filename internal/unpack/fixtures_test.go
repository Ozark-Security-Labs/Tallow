package unpack

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveFixtureCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "archives")
	cases := []struct {
		name string
		kind string
		want RejectCode
		pol  Policy
	}{
		{"tar-traversal.tar", "tar", RejectTraversal, Policy{}},
		{"tar-symlink-escape.tar", "tar", RejectUnsafeLink, Policy{}},
		{"tar-hardlink-escape.tar", "tar", RejectUnsafeLink, Policy{}},
		{"tar-oversize-marker.tar", "tar", RejectMaxFileBytes, Policy{MaxFiles: 10, MaxFileBytes: 3, MaxTotalBytes: 100}},
		{"zip-slip.zip", "zip", RejectTraversal, Policy{}},
		{"wheel-zip-slip.whl", "wheel", RejectTraversal, Policy{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(root, c.name))
			if err != nil {
				t.Fatal(err)
			}
			var m Manifest
			switch c.kind {
			case "tar":
				m, err = ReadTar(c.name, bytes.NewReader(b), c.pol)
			case "zip":
				m, err = ReadZip(c.name, bytes.NewReader(b), int64(len(b)), c.pol)
			case "wheel":
				m, err = ReadWheel(c.name, bytes.NewReader(b), int64(len(b)), c.pol)
			}
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range m.Rejected {
				found = found || r.Rejected == c.want
			}
			if !found {
				t.Fatalf("want rejection %s got %#v", c.want, m.Rejected)
			}
		})
	}
}
