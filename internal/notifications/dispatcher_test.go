package notifications

import (
	"context"
	"errors"
	"net/http"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

type fakeSender struct{ err error }

func (f fakeSender) Send(context.Context, Route, Message) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "provider-1", nil
}

func TestDispatcherRecordsSentAndFailedDeliveries(t *testing.T) {
	recorder := &MemoryRecorder{}
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	d := Dispatcher{Senders: map[Channel]Sender{ChannelEmail: fakeSender{}}, Recorder: recorder, Now: func() time.Time { return now }}
	delivery, err := d.Dispatch(context.Background(), Route{ID: "route-1", Channel: ChannelEmail, Enabled: true}, Message{AlertID: "alert-1", FindingID: "finding-1", Package: "pkg", Version: "1.0.0", Severity: "high", Text: "evidence"})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Status != StatusSent || delivery.ProviderMessageID != "provider-1" || len(recorder.Deliveries) != 1 {
		t.Fatalf("unexpected delivery: %#v recorder=%#v", delivery, recorder.Deliveries)
	}

	d.Senders[ChannelEmail] = fakeSender{err: errors.New("failed password=value webhook_url=https://example.invalid/webhook/abc")}
	delivery, err = d.Dispatch(context.Background(), Route{ID: "route-1", Channel: ChannelEmail, Enabled: true}, Message{})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Status != StatusFailed || strings.Contains(delivery.SanitizedError, "value") || strings.Contains(delivery.SanitizedError, "/webhook/abc") {
		t.Fatalf("error was not sanitized: %#v", delivery)
	}
}

type fakeSMTP struct{ body string }

func (f *fakeSMTP) SendMail(_ string, _ smtp.Auth, _ string, _ []string, msg []byte) error {
	f.body = string(msg)
	return nil
}

func TestEmailChannelSendsRenderedNotification(t *testing.T) {
	smtp := &fakeSMTP{}
	channel := EmailChannel{Config: SMTPConfig{Host: "localhost", Port: 25, From: "tallow@example.com", To: []string{"ops@example.com"}}, Sender: smtpAdapter{smtp}}
	id, err := channel.Send(context.Background(), Route{ID: "route-1"}, Message{Subject: "Review pkg", Text: "Package pkg version 1.0.0 severity high evidence https://tallow.local/..."})
	if err != nil {
		t.Fatal(err)
	}
	if id != "smtp:route-1" || !strings.Contains(smtp.body, "Package pkg") {
		t.Fatalf("unexpected email delivery id=%s body=%s", id, smtp.body)
	}
}

type smtpAdapter struct{ inner *fakeSMTP }

func (s smtpAdapter) SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	return s.inner.SendMail(addr, auth, from, to, msg)
}

type fakeDoer struct{ status int }

func (f fakeDoer) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.status, Body: http.NoBody}, nil
}

func TestTeamsChannelSendsCardWithoutLoggingWebhook(t *testing.T) {
	channel := TeamsChannel{Config: TeamsConfig{WebhookURL: "https://example.invalid/webhook/value"}, Client: fakeDoer{status: 200}}
	id, err := channel.Send(context.Background(), Route{ID: "route-1"}, Message{CardJSON: `{"type":"message","text":"pkg 1.0.0 high rule evidence"}`})
	if err != nil {
		t.Fatal(err)
	}
	if id != "teams:route-1" {
		t.Fatalf("unexpected id %s", id)
	}
}
