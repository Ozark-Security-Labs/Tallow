package unpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

type Entry struct {
	Path      string     `json:"path"`
	Type      string     `json:"type"`
	Size      int64      `json:"size"`
	Mode      int64      `json:"mode"`
	SHA256    string     `json:"sha256,omitempty"`
	LineCount *int       `json:"line_count,omitempty"`
	Rejected  RejectCode `json:"rejected_reason,omitempty"`
}

type Manifest struct {
	ArtifactID    string  `json:"artifact_id"`
	PolicyVersion string  `json:"policy_version"`
	Entries       []Entry `json:"entries"`
	Rejected      []Entry `json:"rejected_entries"`
	Totals        Totals  `json:"totals"`
	Truncated     bool    `json:"truncated"`
}

type Totals struct {
	Files             int   `json:"files"`
	Directories       int   `json:"directories"`
	Rejected          int   `json:"rejected"`
	TotalBytes        int64 `json:"total_bytes"`
	TruncatedByPolicy bool  `json:"truncated_by_policy"`
}

func (m *Manifest) addEntry(e Entry) {
	if e.Rejected != "" {
		m.Rejected = append(m.Rejected, e)
		m.Totals.Rejected++
		return
	}
	m.Entries = append(m.Entries, e)
	if e.Type == "file" {
		m.Totals.Files++
		m.Totals.TotalBytes += e.Size
	}
	if e.Type == "directory" {
		m.Totals.Directories++
	}
}

func (m *Manifest) sort() {
	sort.SliceStable(m.Entries, func(i, j int) bool { return m.Entries[i].Path+m.Entries[i].Type < m.Entries[j].Path+m.Entries[j].Type })
	sort.SliceStable(m.Rejected, func(i, j int) bool {
		return m.Rejected[i].Path+string(m.Rejected[i].Rejected) < m.Rejected[j].Path+string(m.Rejected[j].Rejected)
	})
}

func (m Manifest) JSON() ([]byte, error) {
	m.sort()
	if m.Entries == nil {
		m.Entries = []Entry{}
	}
	if m.Rejected == nil {
		m.Rejected = []Entry{}
	}
	return json.MarshalIndent(m, "", "  ")
}

func fileSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func lineCount(b []byte) *int {
	count := 0
	for _, c := range b {
		if c == '\n' {
			count++
		}
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		count++
	}
	return &count
}
