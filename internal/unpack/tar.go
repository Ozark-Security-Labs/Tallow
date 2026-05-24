package unpack

import (
	"archive/tar"
	"compress/gzip"
	"io"
)

func ReadTar(artifactID string, r io.Reader, policy Policy) (Manifest, error) {
	return readTar(artifactID, tar.NewReader(r), policy.withDefaults())
}

func ReadTgz(artifactID string, r io.Reader, policy Policy) (Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return Manifest{}, err
	}
	defer gz.Close()
	return readTar(artifactID, tar.NewReader(gz), policy.withDefaults())
}

func readTar(artifactID string, tr *tar.Reader, policy Policy) (Manifest, error) {
	m := Manifest{ArtifactID: artifactID, PolicyVersion: PolicyVersion}
	seen := 0
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			m.addEntry(Entry{Rejected: RejectMalformedEntry})
			m.Truncated = true
			m.Totals.TruncatedByPolicy = true
			break
		}
		if seen >= policy.MaxFiles {
			m.addEntry(Entry{Path: h.Name, Size: h.Size, Mode: int64(h.Mode), Rejected: RejectMaxFiles})
			m.Truncated = true
			m.Totals.TruncatedByPolicy = true
			continue
		}
		seen++
		name, code, ok := normalizeArchivePath(h.Name)
		if !ok {
			m.addEntry(Entry{Path: h.Name, Type: "unknown", Size: h.Size, Mode: int64(h.Mode), Rejected: code})
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if unsafeMode(h.Mode) {
				m.addEntry(Entry{Path: name, Type: "directory", Mode: int64(h.Mode), Rejected: RejectUnsafeMode})
				continue
			}
			m.addEntry(Entry{Path: name, Type: "directory", Mode: int64(h.Mode)})
		case tar.TypeReg, tar.TypeRegA:
			if unsafeMode(h.Mode) {
				m.addEntry(Entry{Path: name, Type: "file", Size: h.Size, Mode: int64(h.Mode), Rejected: RejectUnsafeMode})
				continue
			}
			if h.Size > policy.MaxFileBytes {
				m.addEntry(Entry{Path: name, Type: "file", Size: h.Size, Mode: int64(h.Mode), Rejected: RejectMaxFileBytes})
				m.Truncated = true
				m.Totals.TruncatedByPolicy = true
				continue
			}
			if total+h.Size > policy.MaxTotalBytes {
				m.addEntry(Entry{Path: name, Type: "file", Size: h.Size, Mode: int64(h.Mode), Rejected: RejectMaxTotalBytes})
				m.Truncated = true
				m.Totals.TruncatedByPolicy = true
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, h.Size))
			if err != nil || int64(len(b)) != h.Size {
				m.addEntry(Entry{Path: name, Type: "file", Size: h.Size, Mode: int64(h.Mode), Rejected: RejectMalformedEntry})
				continue
			}
			total += h.Size
			m.addEntry(Entry{Path: name, Type: "file", Size: h.Size, Mode: int64(h.Mode), SHA256: fileSHA256(b), LineCount: lineCount(b)})
		case tar.TypeSymlink, tar.TypeLink:
			if !safeLinkTarget(name, h.Linkname) {
				m.addEntry(Entry{Path: name, Type: "link", Mode: int64(h.Mode), Rejected: RejectUnsafeLink})
			} else {
				m.addEntry(Entry{Path: name, Type: "link", Mode: int64(h.Mode)})
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			m.addEntry(Entry{Path: name, Type: "device", Mode: int64(h.Mode), Rejected: RejectDevice})
		default:
			m.addEntry(Entry{Path: name, Type: "unknown", Mode: int64(h.Mode), Rejected: RejectMalformedEntry})
		}
	}
	m.sort()
	return m, nil
}
