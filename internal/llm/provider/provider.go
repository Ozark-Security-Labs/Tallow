package provider

import (
	"context"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Request struct {
	RequestID, Model, PromptTemplateVersion, InputDigest string
	Messages                                             []Message
	Timeout                                              time.Duration
}
type Response struct {
	RequestID, ProviderName, ProviderType, Model string
	OutputJSON                                   []byte
	RawOutputDigest                              string
	Latency                                      time.Duration
}

type Provider interface {
	Generate(context.Context, Request) (Response, error)
	Name() string
	Type() string
}
