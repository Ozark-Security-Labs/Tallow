package unpack

import (
	"archive/zip"
	"bytes"
	"testing"
)

func buildZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestZipRejectsZipSlipAndReadsFiles(t *testing.T) {
	data := buildZip(t, map[string]string{"pkg/file.py": "print('static')\n", "../evil.py": "x", "/abs.py": "x"})
	m, err := ReadZip("artifact-zip", bytes.NewReader(data), int64(len(data)), Policy{MaxFiles: 10, MaxFileBytes: 100, MaxTotalBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 1 || m.Entries[0].Path != "pkg/file.py" || m.Entries[0].SHA256 == "" {
		t.Fatalf("bad zip entries %#v", m.Entries)
	}
	if m.Totals.Rejected != 2 {
		t.Fatalf("want two rejections got %#v", m.Rejected)
	}
}

func TestWheelUsesZipPolicyLimits(t *testing.T) {
	data := buildZip(t, map[string]string{"pkg/__init__.py": "abcdef"})
	m, err := ReadWheel("artifact-wheel", bytes.NewReader(data), int64(len(data)), Policy{MaxFiles: 10, MaxFileBytes: 3, MaxTotalBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rejected) != 1 || m.Rejected[0].Rejected != RejectMaxFileBytes {
		t.Fatalf("want max bytes rejection got %#v", m.Rejected)
	}
}
