//go:build integration

package events

import (
	"context"
	"os"
	"testing"
)

func TestNATSReadyIntegration(t *testing.T) {
	url := os.Getenv("TALLOW_TEST_NATS_URL")
	if url == "" {
		url = "nats://localhost:4222"
	}
	b, err := Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Conn.Close()
	if err := b.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}
