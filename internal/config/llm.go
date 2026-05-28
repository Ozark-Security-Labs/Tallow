package config

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	LLMProviderFake             = "fake"
	LLMProviderCLI              = "cli"
	LLMProviderHTTPAPI          = "http_api"
	LLMProviderOpenAICompatible = "openai_compatible"
)

type LLMConfig struct {
	Enabled          bool
	Provider         LLMProviderConfig
	PromptTemplate   string
	RedactionPolicy  string
	MaxEvidenceItems int
	MaxSnippetBytes  int
	TimeoutSeconds   int
	StorePrompts     bool
	StoreOutputs     bool
}

type LLMProviderConfig struct {
	Type      string
	Name      string
	Model     string
	Command   []string
	Endpoint  string
	APIKeyEnv string
}

func DefaultLLMConfig() LLMConfig {
	return LLMConfig{PromptTemplate: "configs/llm/prompts/narrative-v1.yaml", RedactionPolicy: "configs/redaction/default.yaml", MaxEvidenceItems: 20, MaxSnippetBytes: 4096, TimeoutSeconds: 30, StoreOutputs: true}
}

func (c LLMConfig) Validate() error {
	if c.MaxEvidenceItems <= 0 {
		return fmt.Errorf("llm max evidence items must be positive")
	}
	if c.MaxSnippetBytes <= 0 {
		return fmt.Errorf("llm max snippet bytes must be positive")
	}
	if c.TimeoutSeconds <= 0 {
		return fmt.Errorf("llm timeout seconds must be positive")
	}
	if strings.TrimSpace(c.PromptTemplate) == "" {
		return fmt.Errorf("llm prompt template required")
	}
	if strings.TrimSpace(c.RedactionPolicy) == "" {
		return fmt.Errorf("llm redaction policy required")
	}
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Provider.Type) == "" || strings.TrimSpace(c.Provider.Name) == "" || strings.TrimSpace(c.Provider.Model) == "" {
		return fmt.Errorf("enabled llm provider requires type, name, and model")
	}
	switch c.Provider.Type {
	case LLMProviderFake:
		return nil
	case LLMProviderCLI:
		if len(c.Provider.Command) == 0 || strings.TrimSpace(c.Provider.Command[0]) == "" {
			return fmt.Errorf("enabled cli llm provider requires command argv")
		}
	case LLMProviderHTTPAPI, LLMProviderOpenAICompatible:
		u, err := url.Parse(c.Provider.Endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("enabled api llm provider requires https endpoint")
		}
		if strings.TrimSpace(c.Provider.APIKeyEnv) == "" {
			return fmt.Errorf("enabled api llm provider requires api key env name")
		}
	default:
		return fmt.Errorf("unknown llm provider type %q", c.Provider.Type)
	}
	return nil
}
