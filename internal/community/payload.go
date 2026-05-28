package community

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Payload struct {
	SchemaVersion  string          `json:"schema_version"`
	SharingEnabled bool            `json:"sharing_enabled"`
	GeneratedAt    time.Time       `json:"generated_at"`
	Producer       Producer        `json:"producer"`
	Signals        []PayloadSignal `json:"signals"`
	Privacy        Privacy         `json:"privacy"`
}
type Producer struct {
	InstanceIDHash     string `json:"instance_id_hash"`
	OrganizationIDHash string `json:"organization_id_hash,omitempty"`
	TallowVersion      string `json:"tallow_version"`
}
type PayloadSignal struct {
	SignalID         string `json:"signal_id"`
	Ecosystem        string `json:"ecosystem"`
	PackageNameHash  string `json:"package_name_hash"`
	RuleID           string `json:"rule_id"`
	SignalType       string `json:"signal_type"`
	ObservedAtCoarse string `json:"observed_at_coarse"`
	EvidenceDigest   string `json:"evidence_digest"`
	Confidence       string `json:"confidence,omitempty"`
}
type Privacy struct {
	RawArtifactsIncluded     bool   `json:"raw_artifacts_included"`
	PrivateRepoNamesIncluded bool   `json:"private_repo_names_included"`
	UsersIncluded            bool   `json:"users_included"`
	SecretsIncluded          bool   `json:"secrets_included"`
	RedactionPolicyVersion   string `json:"redaction_policy_version"`
}

type BuildSignalInput struct {
	SignalID, Ecosystem, PackageName, RuleID, SignalType, EvidenceDigest, Confidence string
	ObservedAt                                                                       time.Time
	RawArtifact, PrivateRepoName, User, Secret                                       string
}

func BuildPayload(opt OptIn, instanceID, tallowVersion string, now time.Time, inputs []BuildSignalInput) (Payload, error) {
	p := Payload{SchemaVersion: "community-signals/v1", SharingEnabled: opt.Enabled, GeneratedAt: now.UTC(), Producer: Producer{InstanceIDHash: hashWithSalt("instance", instanceID), OrganizationIDHash: hashWithSalt(instanceID, opt.OrganizationID), TallowVersion: tallowVersion}, Privacy: Privacy{RedactionPolicyVersion: "redaction-v1"}}
	if !opt.Enabled {
		return p, nil
	}
	for _, in := range inputs {
		if in.RawArtifact != "" || in.PrivateRepoName != "" || in.User != "" || in.Secret != "" {
			return Payload{}, fmt.Errorf("private fields are not allowed in community signal payload")
		}
		p.Signals = append(p.Signals, PayloadSignal{SignalID: in.SignalID, Ecosystem: in.Ecosystem, PackageNameHash: hashWithSalt(instanceID, in.PackageName), RuleID: in.RuleID, SignalType: in.SignalType, ObservedAtCoarse: coarseHour(in.ObservedAt), EvidenceDigest: in.EvidenceDigest, Confidence: in.Confidence})
	}
	return p, ValidatePayload(p)
}
func ValidatePayload(p Payload) error {
	if p.Privacy.RawArtifactsIncluded || p.Privacy.PrivateRepoNamesIncluded || p.Privacy.UsersIncluded || p.Privacy.SecretsIncluded {
		return fmt.Errorf("privacy flags must be false")
	}
	for _, s := range p.Signals {
		if strings.Contains(s.PackageNameHash, "/") || strings.Contains(s.PackageNameHash, "@") {
			return fmt.Errorf("package name must be hashed")
		}
		if s.Ecosystem == "" || s.RuleID == "" || s.ObservedAtCoarse == "" {
			return fmt.Errorf("required signal field missing")
		}
	}
	return nil
}
func hashWithSalt(salt, s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(salt + "\x00" + s))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func coarseHour(t time.Time) string {
	u := t.UTC().Truncate(time.Hour)
	return u.Format("2006-01-02T15:00:00Z")
}
