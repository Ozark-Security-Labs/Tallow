package npm

import (
	"bytes"
	"path"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/digest"
)

const (
	VerificationVerified = "verified"
	TrustRegistrySRI     = "registry_sri"
	TrustShasumFallback  = "registry_shasum_lower_trust"
)

func VerifyTarballBytes(artifactID, integrity, shasum string, b []byte) (Verification, map[string]string, map[string]string, error) {
	local, err := digest.ComputeSet(bytes.NewReader(b), digest.AlgorithmSHA1, digest.AlgorithmSHA256, digest.AlgorithmSHA512)
	if err != nil {
		return Verification{}, nil, nil, err
	}
	registry := map[string]string{}
	if strings.TrimSpace(integrity) != "" {
		expected, err := digest.PreferredSRI(integrity)
		if err != nil {
			return Verification{}, registry, local, err
		}
		expected.ArtifactID = artifactID
		_, err = digest.Verify(bytes.NewReader(b), expected)
		registry[expected.Algorithm] = expected.Hex
		if err != nil {
			return Verification{}, registry, local, err
		}
		return Verification{Status: VerificationVerified, Source: "npm-registry", Trust: TrustRegistrySRI}, registry, local, nil
	}
	if strings.TrimSpace(shasum) != "" {
		expected := digest.Expected{Algorithm: digest.AlgorithmSHA1, Hex: shasum, Source: "npm-shasum", ArtifactID: artifactID}
		_, err := digest.Verify(bytes.NewReader(b), expected)
		registry[digest.AlgorithmSHA1] = strings.ToLower(strings.TrimSpace(shasum))
		if err != nil {
			return Verification{}, registry, local, err
		}
		return Verification{Status: VerificationVerified, Source: "npm-registry", Trust: TrustShasumFallback}, registry, local, nil
	}
	return Verification{Status: "unverified_missing_registry_hash", Source: "npm-registry", Trust: "none"}, registry, local, nil
}

func filenameFromTarballURL(raw string) string {
	clean := strings.Split(raw, "?")[0]
	return path.Base(clean)
}
