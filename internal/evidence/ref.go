package evidence

import (
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"path/filepath"
	"strings"
)

type Ref struct {
	Kind            string `json:"kind"`
	ArtifactID      string `json:"artifact_id"`
	SnapshotID      string `json:"snapshot_id,omitempty"`
	Path            string `json:"path,omitempty"`
	StartLine       int    `json:"start_line,omitempty"`
	EndLine         int    `json:"end_line,omitempty"`
	StartByte       int64  `json:"start_byte,omitempty"`
	EndByte         int64  `json:"end_byte,omitempty"`
	Hash            string `json:"hash,omitempty"`
	Excerpt         string `json:"excerpt,omitempty"`
	ExcerptRedacted *bool  `json:"excerpt_redacted,omitempty"`
	Description     string `json:"description,omitempty"`
}

func (r Ref) Validate() error {
	if r.ArtifactID == "" {
		return tallowerr.New(tallowerr.CodeValidation, "artifact_id required")
	}
	if r.Path != "" {
		if filepath.IsAbs(r.Path) || strings.Contains(r.Path, "\\") || strings.Contains(r.Path, "..") {
			return tallowerr.New(tallowerr.CodeValidation, "unsafe evidence path")
		}
	}
	if r.StartLine < 0 || r.EndLine < 0 || r.StartByte < 0 || r.EndByte < 0 {
		return tallowerr.New(tallowerr.CodeValidation, "negative evidence range")
	}
	if r.Excerpt != "" && r.ExcerptRedacted == nil {
		return tallowerr.New(tallowerr.CodeValidation, "excerpt redaction status required")
	}
	return nil
}
