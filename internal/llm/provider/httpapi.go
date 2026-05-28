package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type HTTPAPI struct {
	ProviderType, ProviderName, ModelName, Endpoint, APIKeyEnv string
	Client                                                     *http.Client
}

func (h *HTTPAPI) Name() string { return h.ProviderName }
func (h *HTTPAPI) Type() string { return h.ProviderType }
func (h *HTTPAPI) Generate(ctx context.Context, req Request) (Response, error) {
	u, err := url.Parse(h.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Response{}, fmt.Errorf("https llm endpoint required")
	}
	payload, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if h.APIKeyEnv != "" {
		if key := os.Getenv(h.APIKeyEnv); key != "" {
			httpReq.Header.Set("Authorization", "Bearer "+key)
		}
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: req.Timeout}
	}
	start := time.Now()
	res, err := client.Do(httpReq)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return Response{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return Response{}, fmt.Errorf("llm api returned status %d", res.StatusCode)
	}
	sum := sha256.Sum256(out)
	return Response{RequestID: req.RequestID, ProviderName: h.ProviderName, ProviderType: h.ProviderType, Model: h.ModelName, OutputJSON: out, RawOutputDigest: hex.EncodeToString(sum[:]), Latency: time.Since(start)}, nil
}
