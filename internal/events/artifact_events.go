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
	switch eventType {
	case "artifact.downloaded":
		if a.StorageURI == "" {
			return Envelope{}, tallowerr.New(tallowerr.CodeValidation, "downloaded event requires storage_uri")
		}
	case "artifact.hash.verified":
		if len(a.RegistryHashes) == 0 || len(a.LocalHashes) == 0 {
			return Envelope{}, tallowerr.New(tallowerr.CodeValidation, "hash verified event requires hash evidence")
		}
	case "artifact.hash.mismatch":
		if len(a.RegistryHashes) == 0 || len(a.LocalHashes) == 0 || a.Reason == "" {
			return Envelope{}, tallowerr.New(tallowerr.CodeValidation, "hash mismatch event requires hash evidence and reason")
		}
	}
	b, err := json.Marshal(a)
	if err != nil {
		return Envelope{}, err
	}
	return NewEnvelope(eventType, b), nil
}
