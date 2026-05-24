package identity

import (
	"fmt"
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPyPI Ecosystem = "pypi"
)

type PackageIdentity struct {
	Ecosystem      Ecosystem `json:"ecosystem"`
	RawName        string    `json:"raw_name"`
	NormalizedName string    `json:"normalized_name"`
	Namespace      string    `json:"namespace,omitempty"`
	Name           string    `json:"name"`
	RegistryURL    string    `json:"registry_url"`
}

func (p PackageIdentity) Validate() error {
	if p.Ecosystem != EcosystemNPM && p.Ecosystem != EcosystemPyPI {
		return tallowerr.New(tallowerr.CodeValidation, "unsupported ecosystem")
	}
	if p.RawName == "" || p.NormalizedName == "" || p.Name == "" {
		return tallowerr.New(tallowerr.CodeValidation, "package name fields required")
	}
	if hasBad(p.RawName) || hasBad(p.NormalizedName) {
		return tallowerr.New(tallowerr.CodeValidation, "unsafe package name")
	}
	u, err := url.Parse(p.RegistryURL)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return tallowerr.New(tallowerr.CodeValidation, "unsafe registry url")
	}
	return nil
}
func hasBad(s string) bool {
	return strings.ContainsAny(s, "\\\x00\n\r\t") || strings.Contains(s, "..")
}

type PackageIdentityParts struct{ NormalizedName, Namespace, Name string }

var ascii = regexp.MustCompile(`^[A-Za-z0-9._~@/+-]+$`)

func NormalizePackageName(ec Ecosystem, raw string) (PackageIdentityParts, error) {
	r := strings.TrimSpace(raw)
	if r == "" || !ascii.MatchString(r) || strings.ContainsAny(r, "\\") || strings.Contains(r, "..") || strings.ContainsAny(r, " \t\n\r") {
		return PackageIdentityParts{}, tallowerr.New(tallowerr.CodeValidation, "unsafe package name")
	}
	switch ec {
	case EcosystemNPM:
		l := strings.ToLower(r)
		if strings.HasPrefix(l, "@") {
			parts := strings.Split(l, "/")
			if len(parts) != 2 || len(parts[0]) < 2 || parts[1] == "" {
				return PackageIdentityParts{}, tallowerr.New(tallowerr.CodeValidation, "invalid npm scope")
			}
			return PackageIdentityParts{NormalizedName: l, Namespace: strings.TrimPrefix(parts[0], "@"), Name: parts[1]}, nil
		}
		if strings.Contains(l, "/") {
			return PackageIdentityParts{}, tallowerr.New(tallowerr.CodeValidation, "invalid npm name")
		}
		return PackageIdentityParts{NormalizedName: l, Name: l}, nil
	case EcosystemPyPI:
		if strings.Contains(r, "/") {
			return PackageIdentityParts{}, tallowerr.New(tallowerr.CodeValidation, "invalid pypi name")
		}
		l := strings.ToLower(r)
		re := regexp.MustCompile(`[-_.]+`)
		n := re.ReplaceAllString(l, "-")
		return PackageIdentityParts{NormalizedName: n, Name: n}, nil
	default:
		return PackageIdentityParts{}, tallowerr.New(tallowerr.CodeValidation, "unsupported ecosystem")
	}
}

type VersionStatus string

const (
	StatusNormalized VersionStatus = "normalized"
	StatusWarning    VersionStatus = "stored_with_warning"
	StatusRejected   VersionStatus = "rejected"
)

type VersionIdentity struct {
	RawVersion, NormalizedVersion string
	NormalizationStatus           VersionStatus
	Warnings                      []string
}

func NormalizeVersion(ec Ecosystem, raw string) VersionIdentity {
	trimmed := strings.TrimSpace(raw)
	v := VersionIdentity{RawVersion: raw, NormalizedVersion: trimmed, NormalizationStatus: StatusNormalized}
	if trimmed == "" || strings.ContainsAny(trimmed, "/\\\x00\n\r\t") {
		v.NormalizationStatus = StatusRejected
		v.Warnings = []string{"invalid version syntax"}
		return v
	}
	if ec == EcosystemPyPI && strings.ContainsAny(trimmed, "+!") {
		v.NormalizationStatus = StatusWarning
		v.Warnings = []string{"pep440 boundary stored without full parser"}
	}
	return v
}

type ArtifactKind string

const (
	ArtifactNPMTGZ    ArtifactKind = "npm_tgz"
	ArtifactPyPISDist ArtifactKind = "pypi_sdist"
	ArtifactPyPIWheel ArtifactKind = "pypi_wheel"
)

type ArtifactIdentity struct {
	Kind                                        ArtifactKind
	Filename, DownloadURL, Version, RegistryURL string
	Digests                                     map[string]string
	ObservedAt                                  time.Time
}

func (a ArtifactIdentity) Validate() error {
	if a.Kind != ArtifactNPMTGZ && a.Kind != ArtifactPyPISDist && a.Kind != ArtifactPyPIWheel {
		return tallowerr.New(tallowerr.CodeValidation, "invalid artifact kind")
	}
	if a.Filename == "" || strings.ContainsAny(a.Filename, "/\\\x00\n\r") || strings.Contains(a.Filename, "..") {
		return tallowerr.New(tallowerr.CodeValidation, "unsafe filename")
	}
	u, err := url.Parse(a.DownloadURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return tallowerr.New(tallowerr.CodeValidation, "unsafe download url")
	}
	if a.ObservedAt.IsZero() {
		return tallowerr.New(tallowerr.CodeValidation, "observed_at required")
	}
	return nil
}
func (a ArtifactIdentity) PreDownloadKey() string {
	return fmt.Sprintf("%s|%s|%s", a.Kind, a.Filename, a.DownloadURL)
}
func (a ArtifactIdentity) ImmutableKey() string {
	return fmt.Sprintf("%s|%s|%s", a.Kind, a.Filename, a.Digests["sha256"])
}
