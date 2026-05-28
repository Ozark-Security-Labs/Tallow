package notifications

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type TeamsConfig struct {
	WebhookURLRef string
	WebhookURL    string
}

type TeamsChannel struct {
	Config TeamsConfig
	Client HTTPDoer
}

func (c TeamsChannel) Send(ctx context.Context, route Route, msg Message) (string, error) {
	if c.Client == nil {
		return "", fmt.Errorf("teams client unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Config.WebhookURL, bytes.NewBufferString(msg.CardJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("teams delivery failed: %s", Redact(err.Error()))
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("teams delivery failed: status %d", res.StatusCode)
	}
	return "teams:" + route.ID, nil
}
