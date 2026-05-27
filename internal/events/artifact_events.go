package events

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

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

func (a ArtifactEvent) ValidateAnalysisRequest() error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.StorageURI == "" {
		return tallowerr.New(tallowerr.CodeValidation, "analysis request requires snapshot storage_uri")
	}
	if strings.Contains(a.StorageURI, "://") {
		return tallowerr.New(tallowerr.CodeValidation, "analysis request storage_uri must be a local snapshot path")
	}
	if !sha256Pattern.MatchString(a.LocalHashes["sha256"]) {
		return tallowerr.New(tallowerr.CodeValidation, "analysis request requires local sha256")
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

func NewAnalysisRequestedEnvelope(a ArtifactEvent) (Envelope, error) {
	if err := a.ValidateAnalysisRequest(); err != nil {
		return Envelope{}, err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return Envelope{}, err
	}
	return NewEnvelope("analysis.requested", b), nil
}
