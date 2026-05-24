package events

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Ozark-Security-Labs/Tallow/internal/requestid"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"strings"
	"time"
)

type Trace struct {
	TraceID   string `json:"trace_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}
type Envelope struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Version    string          `json:"version"`
	OccurredAt time.Time       `json:"occurred_at"`
	Producer   string          `json:"producer"`
	Trace      Trace           `json:"trace"`
	Data       json.RawMessage `json:"data"`
}

func ValidateEnvelopeVersion(v string) error {
	if !strings.HasPrefix(v, "1.") {
		return tallowerr.New(tallowerr.CodeValidation, "unknown event major version")
	}
	return nil
}
func (e Envelope) Validate() error {
	if e.ID == "" || e.Type == "" || e.Version == "" || e.Producer == "" || len(e.Data) == 0 {
		return tallowerr.New(tallowerr.CodeValidation, "missing envelope field")
	}
	return ValidateEnvelopeVersion(e.Version)
}
func WithRequestID(ctx context.Context, e Envelope) Envelope {
	if e.Trace.RequestID == "" {
		if id, ok := requestid.FromContext(ctx); ok {
			e.Trace.RequestID = id
		}
	}
	return e
}
func Subject(domain, entity, action string, major int) string {
	return fmt.Sprintf("%s.%s.%s.v%d", domain, entity, action, major)
}

type ArtifactObserved struct {
	Package        any               `json:"package"`
	Version        any               `json:"version"`
	Artifact       any               `json:"artifact"`
	RegistryHashes map[string]string `json:"registry_hashes"`
	LocalHashes    map[string]string `json:"local_hashes,omitempty"`
	StorageRef     string            `json:"storage_ref,omitempty"`
	Source         string            `json:"source"`
	ObservedAt     time.Time         `json:"observed_at"`
}

func (a ArtifactObserved) Validate() error {
	if a.Package == nil || a.Artifact == nil || a.Source == "" || len(a.RegistryHashes) == 0 {
		return tallowerr.New(tallowerr.CodeValidation, "artifact observation missing source or hash")
	}
	return nil
}
