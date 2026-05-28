package provider

import (
	"context"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"testing"
)

func TestRegistrySupportsMilestoneProviderModes(t *testing.T) {
	for _, typ := range []string{config.LLMProviderFake, config.LLMProviderCLI, config.LLMProviderAPI, config.LLMProviderOpenAICompatible} {
		cfg := config.LLMProviderConfig{Type: typ, Name: "p", Model: "m", Command: []string{"echo"}, Endpoint: "https://example.invalid/llm", APIKeyEnv: "KEY"}
		p, err := New(cfg)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if p.Type() == "" {
			t.Fatalf("%s empty type", typ)
		}
	}
}

func TestFakeProviderNoNetwork(t *testing.T) {
	p := &Fake{ProviderName: "fake", ModelName: "test"}
	res, err := p.Generate(context.Background(), Request{RequestID: "r", Model: "test"})
	if err != nil || len(res.OutputJSON) == 0 || res.RawOutputDigest == "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
