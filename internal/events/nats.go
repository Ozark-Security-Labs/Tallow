package events

import (
	"context"
	"encoding/json"
	"github.com/Ozark-Security-Labs/Tallow/internal/requestid"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"github.com/nats-io/nats.go"
	"time"
)

type Bus struct {
	Conn *nats.Conn
	JS   nats.JetStreamContext
}

func Connect(ctx context.Context, url string) (*Bus, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &Bus{Conn: nc, JS: js}, nil
}
func (b *Bus) Ready(ctx context.Context) error {
	_, err := b.JS.AccountInfo()
	if err != nil {
		return tallowerr.Wrap(tallowerr.CodeEventBusUnavailable, "jetstream unavailable", err)
	}
	return nil
}

type Publisher struct{ JS nats.JetStreamContext }

func (p Publisher) Publish(ctx context.Context, subject string, e Envelope) error {
	e = WithRequestID(ctx, e)
	if err := e.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = p.JS.Publish(subject, b, nats.Context(ctx))
	return err
}

type Handler func(context.Context, Envelope) error
type Consumer struct {
	Seen   func(string) bool
	Handle Handler
}

func (c Consumer) Process(ctx context.Context, msg *nats.Msg) error {
	var e Envelope
	if err := json.Unmarshal(msg.Data, &e); err != nil {
		return err
	}
	if c.Seen != nil && c.Seen(e.ID) {
		return msg.Ack()
	}
	if c.Handle != nil {
		if err := c.Handle(ctx, e); err != nil {
			return err
		}
	}
	return msg.Ack()
}
func NewEnvelope(t string, data []byte) Envelope {
	id := requestid.New()
	return Envelope{ID: id, Type: t, Version: "1.0", OccurredAt: time.Now().UTC(), Producer: "tallow", Trace: Trace{TraceID: id}, Data: data}
}
