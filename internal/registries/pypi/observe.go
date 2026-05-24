package pypi

import (
	"bytes"
	"strings"

	"golang.org/x/crypto/blake2b"

	"github.com/Ozark-Security-Labs/Tallow/internal/digest"
)

const (
	ArtifactKindSdist = "pypi_sdist"
	ArtifactKindWheel = "pypi_wheel"
	Verified          = "verified"
)

func VerifyFileBytes(artifactID string, claims map[string]string, b []byte) (Verification, map[string]string, map[string]string, error) {
	local, err := digest.ComputeSet(bytes.NewReader(b), digest.AlgorithmSHA256, digest.AlgorithmSHA512)
	if err != nil {
		return Verification{}, nil, nil, err
	}
	registry := map[string]string{}
	if claims == nil {
		return Verification{Status: "unverified_missing_registry_hash", Source: "pypi-json-api", Trust: "none"}, registry, local, nil
	}
	if want := strings.ToLower(strings.TrimSpace(claims["sha256"])); want != "" {
		registry[digest.AlgorithmSHA256] = want
		_, err := digest.Verify(bytes.NewReader(b), digest.Expected{Algorithm: digest.AlgorithmSHA256, Hex: want, Source: "pypi-json-api", ArtifactID: artifactID})
		if err != nil {
			return Verification{}, registry, local, err
		}
		if blake := strings.ToLower(strings.TrimSpace(claims["blake2b_256"])); blake != "" {
			registry["blake2b_256"] = blake
			local["blake2b_256"] = blake2b256Hex(b)
			if local["blake2b_256"] != blake {
				return Verification{}, registry, local, &digest.MismatchError{Algorithm: "blake2b_256", Expected: blake, Actual: local["blake2b_256"], Source: "pypi-json-api", ArtifactID: artifactID}
			}
		}
		return Verification{Status: Verified, Source: "pypi-json-api", Trust: "registry_sha256"}, registry, local, nil
	}
	return Verification{Status: "unverified_missing_registry_hash", Source: "pypi-json-api", Trust: "none"}, registry, local, nil
}

func ArtifactKind(packageType string) string {
	switch packageType {
	case "sdist":
		return ArtifactKindSdist
	case "bdist_wheel":
		return ArtifactKindWheel
	default:
		return packageType
	}
}

func blake2b256Hex(b []byte) string {
	sum := blake2b.Sum256(b)
	return strings.ToLower(fmtHex(sum[:]))
}

func fmtHex(b []byte) string {
	const table = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = table[c>>4]
		out[i*2+1] = table[c&0x0f]
	}
	return string(out)
}
