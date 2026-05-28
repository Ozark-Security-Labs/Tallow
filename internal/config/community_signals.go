package config

import (
	"fmt"
	"strings"
)

type CommunitySignalsConfig struct{ Sharing CommunitySignalSharingConfig }
type CommunitySignalSharingConfig struct {
	Enabled              bool
	OrganizationID       string
	AllowedSignalClasses []string
	AnonymizationLevel   string
}

func DefaultCommunitySignalsConfig() CommunitySignalsConfig {
	return CommunitySignalsConfig{Sharing: CommunitySignalSharingConfig{Enabled: false, AnonymizationLevel: "coarse", AllowedSignalClasses: []string{}}}
}
func (c CommunitySignalsConfig) Validate() error {
	if !c.Sharing.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Sharing.OrganizationID) == "" {
		return fmt.Errorf("community signal organization id required when sharing enabled")
	}
	switch c.Sharing.AnonymizationLevel {
	case "coarse", "hashed", "public_only":
	default:
		return fmt.Errorf("invalid community signal anonymization level")
	}
	return nil
}
