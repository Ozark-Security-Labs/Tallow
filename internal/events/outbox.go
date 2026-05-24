package events

import (
	"context"
	"encoding/json"
	"sync"
)

type Outbox struct {
	mu   sync.Mutex
	rows map[string][]byte
}

func NewOutbox() *Outbox { return &Outbox{rows: map[string][]byte{}} }
func (o *Outbox) Create(ctx context.Context, subject string, e Envelope) error {
	if err := e.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(struct {
		Subject  string   `json:"subject"`
		Envelope Envelope `json:"envelope"`
	}{subject, e})
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.rows[e.ID]; !ok {
		o.rows[e.ID] = b
	}
	return nil
}
func (o *Outbox) Count() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.rows) }
