package narrative

import (
	"context"
	"time"
)

type Record struct {
	ID                    string
	FindingIDs            []string
	CanonicalSeverity     string
	ProviderType          string
	ProviderName          string
	Model                 string
	PromptTemplateVersion string
	InputDigest           string
	OutputDigest          string
	Output                Output
	ValidationStatus      string
	RejectionReason       string
	CreatedAt             time.Time
}
type Store interface {
	Save(context.Context, Record) error
	List(context.Context) ([]Record, error)
}
type MemoryStore struct{ Records []Record }

func (m *MemoryStore) Save(_ context.Context, r Record) error {
	m.Records = append(m.Records, r)
	return nil
}
func (m *MemoryStore) List(_ context.Context) ([]Record, error) {
	out := append([]Record(nil), m.Records...)
	return out, nil
}
