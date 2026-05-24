package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/identity"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
)

const Prefix = "fs://artifacts"

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ArtifactRawURI(pkg identity.PackageIdentity, version identity.VersionIdentity, artifact identity.ArtifactIdentity, sha256Hex string) (string, error) {
	if err := pkg.Validate(); err != nil {
		return "", err
	}
	if err := artifact.Validate(); err != nil {
		return "", err
	}
	if !hex64.MatchString(sha256Hex) {
		return "", tallowerr.New(tallowerr.CodeValidation, "invalid artifact sha256")
	}
	if err := safeComponent(string(pkg.Ecosystem)); err != nil {
		return "", err
	}
	pkgKey := strings.Join([]string{string(pkg.Ecosystem), pkg.RegistryURL, pkg.NormalizedName}, "|")
	verKey := strings.Join([]string{pkg.NormalizedName, version.RawVersion, version.NormalizedVersion, string(artifact.Kind), artifact.Filename}, "|")
	return fmt.Sprintf("%s/raw/%s/%s/%s/%s", Prefix, pkg.Ecosystem, digestKey(pkgKey), digestKey(verKey), sha256Hex), nil
}

func ManifestURI(artifactID string) (string, error) {
	if err := safeComponent(artifactID); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/manifests/%s.json", Prefix, artifactID), nil
}

func SnapshotURI(artifactID string) (string, error) {
	if err := safeComponent(artifactID); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/snapshots/%s.json", Prefix, artifactID), nil
}

func DiffURI(fromArtifactID, toArtifactID string) (string, error) {
	if err := safeComponent(fromArtifactID); err != nil {
		return "", err
	}
	if err := safeComponent(toArtifactID); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/diffs/%s/%s.json", Prefix, fromArtifactID, toArtifactID), nil
}

func safeComponent(v string) error {
	if v == "" || strings.HasPrefix(v, "/") || strings.Contains(v, "..") || strings.ContainsAny(v, "/\\\x00\n\r\t") || !safeID.MatchString(v) {
		return tallowerr.New(tallowerr.CodeValidation, "unsafe storage uri component")
	}
	return nil
}

func digestKey(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
