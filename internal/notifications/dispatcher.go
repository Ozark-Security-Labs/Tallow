package notifications

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Dispatcher struct {
	Senders  map[Channel]Sender
	Recorder Recorder
	Now      func() time.Time
}

func (d Dispatcher) Dispatch(ctx context.Context, route Route, msg Message) (Delivery, error) {
	now := d.now()
	delivery := Delivery{ID: "del_" + now.Format("20060102150405.000000000"), RouteID: route.ID, AlertID: msg.AlertID, FindingID: msg.FindingID, Channel: route.Channel, Status: StatusPending, Attempts: 1, CreatedAt: now}
	if !route.Enabled {
		delivery.Status = StatusFailed
		delivery.SanitizedError = "route disabled"
		return delivery, d.record(ctx, delivery)
	}
	sender := d.Senders[route.Channel]
	if sender == nil {
		delivery.Status = StatusFailed
		delivery.SanitizedError = "sender unavailable"
		return delivery, d.record(ctx, delivery)
	}
	providerID, err := sender.Send(ctx, route, msg)
	if err != nil {
		delivery.Status = StatusFailed
		delivery.SanitizedError = Redact(err.Error())
		return delivery, d.record(ctx, delivery)
	}
	delivery.Status = StatusSent
	delivery.ProviderMessageID = providerID
	delivery.SentAt = now
	return delivery, d.record(ctx, delivery)
}

func (d Dispatcher) record(ctx context.Context, delivery Delivery) error {
	if d.Recorder == nil {
		return nil
	}
	if err := d.Recorder.Record(ctx, delivery); err != nil {
		return fmt.Errorf("record delivery failed: %w", err)
	}
	return nil
}

func (d Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

type MemoryRecorder struct {
	mu         sync.Mutex
	Deliveries []Delivery
}

func (r *MemoryRecorder) Record(_ context.Context, delivery Delivery) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Deliveries = append(r.Deliveries, delivery)
	return nil
}
