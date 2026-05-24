package artifacts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type StoredArtifact struct {
	ArtifactID         string
	StorageURI         string
	Size               int64
	MediaType          string
	RegistryDigests    map[string]string
	LocalDigests       map[string]string
	VerificationStatus VerificationStatus
}

type FileStore struct{ Root string }

func (s FileStore) Write(uri string, b []byte) (StoredArtifact, error) {
	if !strings.HasPrefix(uri, "fs://artifacts/") {
		return StoredArtifact{}, fmt.Errorf("unsupported storage uri")
	}
	rel := strings.TrimPrefix(uri, "fs://artifacts/")
	clean := filepath.Clean(rel)
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return StoredArtifact{}, fmt.Errorf("unsafe storage uri")
	}
	path := filepath.Join(s.Root, clean)
	rootClean, _ := filepath.Abs(s.Root)
	pathClean, _ := filepath.Abs(path)
	if !strings.HasPrefix(pathClean, rootClean+string(os.PathSeparator)) && pathClean != rootClean {
		return StoredArtifact{}, fmt.Errorf("storage path escapes root")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return StoredArtifact{}, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return StoredArtifact{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return StoredArtifact{}, err
	}
	return StoredArtifact{StorageURI: uri, Size: int64(len(b))}, nil
}
