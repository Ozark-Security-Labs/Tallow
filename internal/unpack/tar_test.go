package unpack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

func buildTar(t *testing.T, headers ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range headers {
		body := []byte(h.PAXRecords["body"])
		h.PAXRecords = nil
		if h.Size == 0 && body != nil {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestTarManifestAndRejectsUnsafeEntries(t *testing.T) {
	data := buildTar(t,
		&tar.Header{Name: "pkg/file.txt", Mode: 0o644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"body": "hello\n"}},
		&tar.Header{Name: "../evil", Mode: 0o644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"body": "x"}},
		&tar.Header{Name: "/abs", Mode: 0o644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"body": "x"}},
		&tar.Header{Name: "pkg/link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"},
		&tar.Header{Name: "pkg/dev", Mode: 0o644, Typeflag: tar.TypeChar},
		&tar.Header{Name: "pkg/setuid", Mode: 0o4644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"body": "x"}},
	)
	m, err := ReadTar("artifact-1", bytes.NewReader(data), Policy{MaxFiles: 10, MaxFileBytes: 20, MaxTotalBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 1 || m.Entries[0].Path != "pkg/file.txt" || m.Entries[0].SHA256 == "" || *m.Entries[0].LineCount != 1 {
		t.Fatalf("bad entries %#v", m.Entries)
	}
	if m.Totals.Rejected != 5 {
		t.Fatalf("want rejected entries got %#v", m.Rejected)
	}
}

func TestTgzAndLimits(t *testing.T) {
	tarData := buildTar(t, &tar.Header{Name: "big.txt", Mode: 0o644, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"body": "too big"}})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(tarData)
	_ = gw.Close()
	m, err := ReadTgz("artifact-1", bytes.NewReader(gz.Bytes()), Policy{MaxFiles: 10, MaxFileBytes: 3, MaxTotalBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rejected) != 1 || m.Rejected[0].Rejected != RejectMaxFileBytes {
		t.Fatalf("want max file rejection got %#v", m.Rejected)
	}
}
