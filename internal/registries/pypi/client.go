package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/artifacts"
	"github.com/Ozark-Security-Labs/Tallow/internal/identity"
	"github.com/Ozark-Security-Labs/Tallow/internal/storage"
)

type Client struct {
	BaseURL              string
	HTTPClient           *http.Client
	MaxDownloadBytes     int64
	AllowedArtifactHosts []string
	Store                *artifacts.FileStore
}

func NewClient(baseURL string, hc *http.Client) Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: hc, MaxDownloadBytes: 256 << 20}
}

func (c Client) FetchMetadata(ctx context.Context, project string) (Metadata, error) {
	u := c.BaseURL + "/pypi/" + url.PathEscape(project) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Metadata{}, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("pypi metadata status %d", resp.StatusCode)
	}
	if resp.ContentLength > c.maxBytes() {
		return Metadata{}, fmt.Errorf("pypi metadata exceeds max bytes")
	}
	var meta Metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, c.maxBytes()+1)).Decode(&meta); err != nil {
		return Metadata{}, err
	}
	return meta, nil
}

func (c Client) Download(ctx context.Context, rawurl string) ([]byte, error) {
	if err := c.validateArtifactURL(rawurl); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	client := *c.HTTPClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return c.validateArtifactURL(req.URL.String()) }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi artifact status %d", resp.StatusCode)
	}
	if resp.ContentLength > c.maxBytes() {
		return nil, fmt.Errorf("pypi artifact exceeds max bytes")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > c.maxBytes() {
		return nil, fmt.Errorf("pypi artifact exceeds max bytes")
	}
	return b, nil
}

func (c Client) maxBytes() int64 {
	if c.MaxDownloadBytes <= 0 {
		return 256 << 20
	}
	return c.MaxDownloadBytes
}

func (c Client) validateArtifactURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("unsupported artifact url scheme")
	}
	if u.User != nil {
		return fmt.Errorf("artifact url userinfo forbidden")
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	if base.Scheme == "https" && u.Scheme != "https" {
		return fmt.Errorf("artifact url must use https")
	}
	allowed := append([]string{base.Host}, c.AllowedArtifactHosts...)
	if strings.EqualFold(base.Hostname(), "pypi.org") {
		allowed = append(allowed, "files.pythonhosted.org")
	}
	for _, h := range allowed {
		if strings.EqualFold(u.Host, h) || (strings.EqualFold(u.Hostname(), h) && (u.Port() == "" || u.Port() == "443")) {
			return nil
		}
	}
	return fmt.Errorf("artifact url host %s not allowed", u.Host)
}

func (c Client) Observe(ctx context.Context, project, version string) ([]Artifact, error) {
	meta, err := c.FetchMetadata(ctx, project)
	if err != nil {
		return nil, err
	}
	files := meta.Releases[version]
	if len(files) == 0 {
		return nil, fmt.Errorf("pypi version %q not found", version)
	}
	out := make([]Artifact, 0, len(files))
	for _, f := range files {
		if ArtifactKind(f.PackageType) != ArtifactKindSdist && ArtifactKind(f.PackageType) != ArtifactKindWheel {
			continue
		}
		body, err := c.Download(ctx, f.URL)
		if err != nil {
			return nil, err
		}
		artifactID := "pypi:" + meta.Info.Name + "@" + version + ":" + f.Filename
		verification, registry, local, err := VerifyFileBytes(artifactID, f.Digests, body)
		if err != nil {
			return nil, err
		}
		uploaded := time.Time{}
		if f.UploadTimeISO != "" {
			uploaded, _ = time.Parse(time.RFC3339, strings.TrimSuffix(f.UploadTimeISO, "Z")+"Z")
		}
		storageURI := ""
		parts, _ := identity.NormalizePackageName(identity.EcosystemPyPI, meta.Info.Name)
		pkg := identity.PackageIdentity{Ecosystem: identity.EcosystemPyPI, RawName: meta.Info.Name, NormalizedName: parts.NormalizedName, Name: parts.Name, RegistryURL: c.BaseURL}
		kind := identity.ArtifactKind(ArtifactKind(f.PackageType))
		art := identity.ArtifactIdentity{Kind: kind, Filename: f.Filename, DownloadURL: f.URL, Digests: map[string]string{"sha256": local["sha256"]}, ObservedAt: time.Now().UTC()}
		if uri, err := storage.ArtifactRawURI(pkg, identity.NormalizeVersion(identity.EcosystemPyPI, version), art, local["sha256"]); err == nil {
			storageURI = uri
			if c.Store != nil && verification.Status == Verified {
				if _, err := c.Store.Write(uri, body); err != nil {
					return nil, err
				}
			}
		}
		out = append(out, Artifact{Project: meta.Info.Name, Version: version, Filename: f.Filename, Kind: ArtifactKind(f.PackageType), URL: f.URL, Yanked: f.Yanked, YankedReason: f.YankedReason, UploadedAt: uploaded, RegistryHashes: registry, LocalHashes: local, Verification: verification, StorageURI: storageURI})
	}
	return out, nil
}
