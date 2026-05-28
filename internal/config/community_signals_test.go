package config

import "testing"

func TestCommunitySignalsDefaultDisabled(t *testing.T) {
	cfg := Default()
	if cfg.Community.Sharing.Enabled {
		t.Fatal("community sharing must default false")
	}
	if err := cfg.Community.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestCommunitySignalsEnabledRequiresOrgAndValidAnonymization(t *testing.T) {
	cfg := DefaultCommunitySignalsConfig()
	cfg.Sharing.Enabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected org requirement")
	}
	cfg.Sharing.OrganizationID = "org-1"
	cfg.Sharing.AnonymizationLevel = "bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected anonymization validation")
	}
	cfg.Sharing.AnonymizationLevel = "hashed"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
