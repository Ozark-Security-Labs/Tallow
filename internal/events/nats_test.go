package events

import (
	"context"
	"encoding/json"
	"github.com/Ozark-Security-Labs/Tallow/internal/requestid"
	"testing"

	"github.com/nats-io/nats.go"
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

func TestConsumerRejectsInvalidEnvelope(t *testing.T) {
	called := false
	c := Consumer{Handle: func(context.Context, Envelope) error {
		called = true
		return nil
	}}
	msg := &nats.Msg{Data: []byte(`{"id":"evt","type":"test","version":"1.0","producer":"tallow","data":{}}`)}
	if err := c.Process(context.Background(), msg); err == nil {
		t.Fatal("want validation error")
	}
	if called {
		t.Fatal("handler called for invalid envelope")
	}
}

func TestConsumerRejectsInvalidArtifactObservedPayload(t *testing.T) {
	called := false
	e := NewEnvelope("artifact.observed", json.RawMessage(`{"package":{},"version":{},"artifact":{},"registry_hashes":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"source":"registry","observed_at":"2026-05-24T00:00:00Z"}`))
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	c := Consumer{Handle: func(context.Context, Envelope) error {
		called = true
		return nil
	}}
	if err := c.Process(context.Background(), &nats.Msg{Data: b}); err == nil {
		t.Fatal("want payload validation error")
	}
	if called {
		t.Fatal("handler called for invalid payload")
	}
}
