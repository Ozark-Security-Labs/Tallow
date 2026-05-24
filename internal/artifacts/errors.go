package artifacts

import "fmt"

type VerificationStatus string

const (
	StatusVerified                      VerificationStatus = "verified"
	StatusUnverifiedMissingRegistryHash VerificationStatus = "unverified_missing_registry_hash"
	StatusMismatch                      VerificationStatus = "mismatch"
)

type VerificationError struct {
	Status     VerificationStatus
	ArtifactID string
	Reason     string
}

func (e VerificationError) Error() string {
	return fmt.Sprintf("artifact %s verification %s: %s", e.ArtifactID, e.Status, e.Reason)
}
