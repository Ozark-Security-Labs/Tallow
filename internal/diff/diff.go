package diff

import (
	"sort"

	"github.com/Ozark-Security-Labs/Tallow/internal/snapshot"
	"github.com/Ozark-Security-Labs/Tallow/internal/unpack"
)

type FileSummary struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}
type ModifiedFile struct {
	Path string      `json:"path"`
	From FileSummary `json:"from"`
	To   FileSummary `json:"to"`
}
type MetadataDelta struct {
	Key  string `json:"key"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}
type Diff struct {
	ID             string          `json:"id"`
	FromArtifactID string          `json:"from_artifact_id"`
	ToArtifactID   string          `json:"to_artifact_id"`
	Added          []FileSummary   `json:"added"`
	Removed        []FileSummary   `json:"removed"`
	Modified       []ModifiedFile  `json:"modified"`
	MetadataDeltas []MetadataDelta `json:"metadata_deltas"`
}

func Compare(id string, from, to snapshot.Snapshot) Diff {
	fm, tm := mapFiles(from.Files), mapFiles(to.Files)
	d := Diff{ID: id, FromArtifactID: from.ArtifactID, ToArtifactID: to.ArtifactID, Added: []FileSummary{}, Removed: []FileSummary{}, Modified: []ModifiedFile{}, MetadataDeltas: metadataDeltas(from.Metadata, to.Metadata)}
	for p, tf := range tm {
		if _, ok := fm[p]; !ok {
			d.Added = append(d.Added, summary(tf))
		}
	}
	for p, ff := range fm {
		if _, ok := tm[p]; !ok {
			d.Removed = append(d.Removed, summary(ff))
		}
	}
	for p, ff := range fm {
		if tf, ok := tm[p]; ok && (ff.SHA256 != tf.SHA256 || ff.Size != tf.Size || ff.Type != tf.Type) {
			d.Modified = append(d.Modified, ModifiedFile{Path: p, From: summary(ff), To: summary(tf)})
		}
	}
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Path < d.Added[j].Path })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Path < d.Removed[j].Path })
	sort.Slice(d.Modified, func(i, j int) bool { return d.Modified[i].Path < d.Modified[j].Path })
	return d
}

func mapFiles(files []unpack.Entry) map[string]unpack.Entry {
	m := map[string]unpack.Entry{}
	for _, f := range files {
		m[f.Path] = f
	}
	return m
}
func summary(f unpack.Entry) FileSummary {
	return FileSummary{Path: f.Path, Type: f.Type, Size: f.Size, SHA256: f.SHA256}
}
func metadataDeltas(a, b map[string]string) []MetadataDelta {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	out := []MetadataDelta{}
	for k := range keys {
		if a[k] != b[k] {
			out = append(out, MetadataDelta{Key: k, From: a[k], To: b[k]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
