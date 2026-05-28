package config

import "testing"

func TestLLMConfigDefaultsDisabled(t *testing.T) {
	cfg := Default()
	if cfg.LLM.Enabled {
		t.Fatal("llm must be disabled by default")
	}
	if err := cfg.LLM.Validate(); err != nil {
		t.Fatalf("disabled config should validate: %v", err)
	}
}

func TestLLMConfigEnabledValidation(t *testing.T) {
	cfg := DefaultLLMConfig()
	cfg.Enabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("enabled provider without type should fail")
	}
	cfg.Provider = LLMProviderConfig{Type: LLMProviderFake, Name: "fake", Model: "test"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fake provider should validate: %v", err)
	}
	cfg.Provider.Type = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown provider type should fail")
	}
}

func TestLLMConfigProviderRequirements(t *testing.T) {
	cli := DefaultLLMConfig()
	cli.Enabled = true
	cli.Provider = LLMProviderConfig{Type: LLMProviderCLI, Name: "local", Model: "test"}
	if err := cli.Validate(); err == nil {
		t.Fatal("cli provider without command should fail")
	}
	api := DefaultLLMConfig()
	api.Enabled = true
	api.Provider = LLMProviderConfig{Type: LLMProviderAPI, Name: "api", Model: "test", Endpoint: "http://example.com", APIKeyEnv: "TALLOW_KEY"}
	if err := api.Validate(); err == nil {
		t.Fatal("api provider without https should fail")
	}
}
