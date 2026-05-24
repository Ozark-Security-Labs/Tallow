package unpack

import (
	"path"
	"strings"
)

const PolicyVersion = "safe-unpack-v1"

type RejectCode string

const (
	RejectTraversal      RejectCode = "path_traversal"
	RejectAbsolute       RejectCode = "absolute_path"
	RejectUnsafeLink     RejectCode = "unsafe_link"
	RejectDevice         RejectCode = "device_file"
	RejectUnsafeMode     RejectCode = "unsafe_mode"
	RejectMaxFiles       RejectCode = "max_files_exceeded"
	RejectMaxFileBytes   RejectCode = "max_file_bytes_exceeded"
	RejectMaxTotalBytes  RejectCode = "max_total_bytes_exceeded"
	RejectMalformedEntry RejectCode = "malformed_entry"
)

type Policy struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

func DefaultPolicy() Policy {
	return Policy{MaxFiles: 100000, MaxFileBytes: 256 << 20, MaxTotalBytes: 1 << 30}
}

func (p Policy) withDefaults() Policy {
	d := DefaultPolicy()
	if p.MaxFiles <= 0 {
		p.MaxFiles = d.MaxFiles
	}
	if p.MaxFileBytes <= 0 {
		p.MaxFileBytes = d.MaxFileBytes
	}
	if p.MaxTotalBytes <= 0 {
		p.MaxTotalBytes = d.MaxTotalBytes
	}
	return p
}

func normalizeArchivePath(name string) (string, RejectCode, bool) {
	if name == "" || strings.ContainsRune(name, '\x00') {
		return "", RejectMalformedEntry, false
	}
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(name, "/") {
		return name, RejectAbsolute, false
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, "/../") {
		return clean, RejectTraversal, false
	}
	return clean, "", true
}

func safeLinkTarget(entryPath, target string) bool {
	if target == "" || strings.ContainsRune(target, '\x00') || strings.HasPrefix(target, "/") {
		return false
	}
	target = strings.ReplaceAll(target, "\\", "/")
	base := path.Dir(entryPath)
	clean := path.Clean(path.Join(base, target))
	return clean != "." && !strings.HasPrefix(clean, "../") && clean != ".."
}
