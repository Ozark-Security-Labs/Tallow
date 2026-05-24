package events

import (
	"encoding/json"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

type ArtifactEvent struct {
	Ecosystem      string            `json:"ecosystem"`
	Package        string            `json:"package"`
	Version        string            `json:"version"`
	ArtifactID     string            `json:"artifact_id"`
	ArtifactKind   string            `json:"artifact_kind"`
	StorageURI     string            `json:"storage_uri,omitempty"`
	RegistryHashes map[string]string `json:"registry_hashes,omitempty"`
	LocalHashes    map[string]string `json:"local_hashes,omitempty"`
	EvidenceRefs   []string          `json:"evidence_refs,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	ObservedAt     time.Time         `json:"observed_at"`
}

func (a ArtifactEvent) Validate() error {
	if a.Ecosystem == "" || a.Package == "" || a.Version == "" || a.ArtifactID == "" || a.ArtifactKind == "" || a.ObservedAt.IsZero() {
		return tallowerr.New(tallowerr.CodeValidation, "artifact event missing required field")
	}
	return nil
}

func NewArtifactEnvelope(eventType string, a ArtifactEvent) (Envelope, error) {
	if err := a.Validate(); err != nil {
		return Envelope{}, err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return Envelope{}, err
	}
	return NewEnvelope(eventType, b), nil
}
