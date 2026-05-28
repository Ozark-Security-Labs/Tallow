package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

type CLI struct {
	ProviderName, ModelName string
	Command                 []string
}

func (c *CLI) Name() string { return c.ProviderName }
func (c *CLI) Type() string { return "cli" }
func (c *CLI) Generate(ctx context.Context, req Request) (Response, error) {
	if len(c.Command) == 0 {
		return Response{}, fmt.Errorf("cli command required")
	}
	payload, _ := json.Marshal(req)
	start := time.Now()
	cmd := exec.CommandContext(ctx, c.Command[0], c.Command[1:]...)
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		return Response{}, err
	}
	if len(out) > 1<<20 {
		return Response{}, fmt.Errorf("llm cli output exceeds limit")
	}
	sum := sha256.Sum256(out)
	return Response{RequestID: req.RequestID, ProviderName: c.ProviderName, ProviderType: c.Type(), Model: c.ModelName, OutputJSON: out, RawOutputDigest: hex.EncodeToString(sum[:]), Latency: time.Since(start)}, nil
}
