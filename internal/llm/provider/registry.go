package provider

import (
	"fmt"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
)

func New(cfg config.LLMProviderConfig) (Provider, error) {
	switch cfg.Type {
	case config.LLMProviderFake:
		return &Fake{ProviderName: cfg.Name, ModelName: cfg.Model}, nil
	case config.LLMProviderCLI:
		return &CLI{ProviderName: cfg.Name, ModelName: cfg.Model, Command: cfg.Command}, nil
	case config.LLMProviderAPI, config.LLMProviderOpenAICompatible:
		return &HTTPAPI{ProviderType: cfg.Type, ProviderName: cfg.Name, ModelName: cfg.Model, Endpoint: cfg.Endpoint, APIKeyEnv: cfg.APIKeyEnv}, nil
	default:
		return nil, fmt.Errorf("unknown llm provider type %q", cfg.Type)
	}
}
