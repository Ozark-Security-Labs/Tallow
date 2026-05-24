package unpack

import (
	"archive/zip"
	"io"
	"strings"
)

func ReadZip(artifactID string, r io.ReaderAt, size int64, policy Policy) (Manifest, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return Manifest{}, err
	}
	return readZip(artifactID, zr, policy.withDefaults())
}

func ReadWheel(artifactID string, r io.ReaderAt, size int64, policy Policy) (Manifest, error) {
	return ReadZip(artifactID, r, size, policy)
}

func readZip(artifactID string, zr *zip.Reader, policy Policy) (Manifest, error) {
	m := Manifest{ArtifactID: artifactID, PolicyVersion: PolicyVersion}
	var total int64
	seen := 0
	for _, f := range zr.File {
		if seen >= policy.MaxFiles {
			m.addEntry(Entry{Path: f.Name, Size: int64(f.UncompressedSize64), Mode: int64(f.Mode()), Rejected: RejectMaxFiles})
			m.Truncated = true
			m.Totals.TruncatedByPolicy = true
			continue
		}
		seen++
		name, code, ok := normalizeArchivePath(f.Name)
		if !ok {
			m.addEntry(Entry{Path: f.Name, Type: "unknown", Size: int64(f.UncompressedSize64), Mode: int64(f.Mode()), Rejected: code})
			continue
		}
		mode := f.Mode()
		if unsafeMode(int64(mode)) {
			m.addEntry(Entry{Path: name, Type: "file", Size: int64(f.UncompressedSize64), Mode: int64(mode), Rejected: RejectUnsafeMode})
			continue
		}
		if strings.HasSuffix(f.Name, "/") || f.FileInfo().IsDir() {
			m.addEntry(Entry{Path: name, Type: "directory", Mode: int64(mode)})
			continue
		}
		if mode.Type() != 0 && !mode.IsRegular() {
			m.addEntry(Entry{Path: name, Type: "unknown", Size: int64(f.UncompressedSize64), Mode: int64(mode), Rejected: RejectMalformedEntry})
			continue
		}
		size := int64(f.UncompressedSize64)
		if size > policy.MaxFileBytes {
			m.addEntry(Entry{Path: name, Type: "file", Size: size, Mode: int64(mode), Rejected: RejectMaxFileBytes})
			m.Truncated = true
			m.Totals.TruncatedByPolicy = true
			continue
		}
		if total+size > policy.MaxTotalBytes {
			m.addEntry(Entry{Path: name, Type: "file", Size: size, Mode: int64(mode), Rejected: RejectMaxTotalBytes})
			m.Truncated = true
			m.Totals.TruncatedByPolicy = true
			continue
		}
		rc, err := f.Open()
		if err != nil {
			m.addEntry(Entry{Path: name, Type: "file", Size: size, Mode: int64(mode), Rejected: RejectMalformedEntry})
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, size))
		_ = rc.Close()
		if err != nil || int64(len(b)) != size {
			m.addEntry(Entry{Path: name, Type: "file", Size: size, Mode: int64(mode), Rejected: RejectMalformedEntry})
			continue
		}
		total += size
		m.addEntry(Entry{Path: name, Type: "file", Size: size, Mode: int64(mode), SHA256: fileSHA256(b), LineCount: lineCount(b)})
	}
	m.sort()
	return m, nil
}
