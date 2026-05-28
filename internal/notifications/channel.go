package notifications

import (
	"context"
	"time"
)

type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelTeams Channel = "teams"
)

type Status string

const (
	StatusPending Status = "pending"
	StatusSent    Status = "sent"
	StatusFailed  Status = "failed"
)

type Message struct {
	AlertID   string
	FindingID string
	Package   string
	Version   string
	Severity  string
	Subject   string
	Text      string
	HTML      string
	CardJSON  string
}

type Route struct {
	ID                string
	Name              string
	Channel           Channel
	Enabled           bool
	SeverityThreshold string
	Config            map[string]string
}

type Delivery struct {
	ID                string    `json:"id"`
	RouteID           string    `json:"route_id"`
	AlertID           string    `json:"alert_id,omitempty"`
	FindingID         string    `json:"finding_id,omitempty"`
	Channel           Channel   `json:"channel"`
	Status            Status    `json:"status"`
	Attempts          int       `json:"attempts"`
	Provider          string    `json:"provider"`
	SanitizedError    string    `json:"sanitized_error,omitempty"`
	ProviderMessageID string    `json:"provider_message_id,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	SentAt            time.Time `json:"sent_at,omitempty"`
}

type Sender interface {
	Send(context.Context, Route, Message) (string, error)
}

type Recorder interface {
	Record(context.Context, Delivery) error
}
