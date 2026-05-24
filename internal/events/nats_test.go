package events

import (
	"context"
	"encoding/json"
	"github.com/Ozark-Security-Labs/Tallow/internal/requestid"
	"testing"
)

func TestOutboxIdempotent(t *testing.T) {
	e := NewEnvelope("test", json.RawMessage(`{}`))
	o := NewOutbox()
	if err := o.Create(context.Background(), "a.b.c.v1", e); err != nil {
		t.Fatal(err)
	}
	if err := o.Create(context.Background(), "a.b.c.v1", e); err != nil {
		t.Fatal(err)
	}
	if o.Count() != 1 {
		t.Fatal(o.Count())
	}
}
func TestEnvelopeInjectsRequestID(t *testing.T) {
	e := NewEnvelope("test", json.RawMessage(`{}`))
	ctx := requestid.WithContext(context.Background(), "rid")
	if WithRequestID(ctx, e).Trace.RequestID != "rid" {
		t.Fatal()
	}
}
