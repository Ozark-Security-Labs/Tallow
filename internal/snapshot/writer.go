package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/Ozark-Security-Labs/Tallow/internal/unpack"
)

func Build(in Input) Snapshot {
	files := append([]unpack.Entry(nil), in.Manifest.Entries...)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path+files[i].Type < files[j].Path+files[j].Type })
	evidence := append([]string(nil), in.EvidenceRefs...)
	sort.Strings(evidence)
	return Snapshot{ID: in.ID, ArtifactID: in.ArtifactID, ArtifactKind: in.ArtifactKind, Package: in.Package, Version: in.Version, ManifestURI: in.ManifestURI, Metadata: sortedMetadata(in.Metadata), FileInventoryDigest: inventoryDigest(files), Files: files, EvidenceRefs: evidence}
}

func Write(in Input) ([]byte, error) {
	s := Build(in)
	if s.Metadata == nil {
		s.Metadata = map[string]string{}
	}
	if s.Files == nil {
		s.Files = []unpack.Entry{}
	}
	if s.EvidenceRefs == nil {
		s.EvidenceRefs = []string{}
	}
	return json.MarshalIndent(s, "", "  ")
}

func sortedMetadata(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func inventoryDigest(files []unpack.Entry) string {
	b, _ := json.Marshal(files)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
