package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultMaxDownloadBytes int64 = 256 << 20

type Client struct {
	BaseURL          string
	HTTPClient       *http.Client
	MaxDownloadBytes int64
}

func NewClient(baseURL string, hc *http.Client) Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: hc, MaxDownloadBytes: DefaultMaxDownloadBytes}
}

func (c Client) maxBytes() int64 {
	if c.MaxDownloadBytes <= 0 {
		return DefaultMaxDownloadBytes
	}
	return c.MaxDownloadBytes
}

func (c Client) FetchMetadata(ctx context.Context, name string) (Metadata, error) {
	pathName := url.PathEscape(name)
	pathName = strings.ReplaceAll(pathName, "%2F", "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/"+pathName, nil)
	if err != nil {
		return Metadata{}, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	client := *c.HTTPClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return c.validateArtifactURL(req.URL.String()) }
	resp, err := client.Do(req)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("npm metadata status %d", resp.StatusCode)
	}
	var meta Metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, c.maxBytes())).Decode(&meta); err != nil {
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
		return nil, fmt.Errorf("npm tarball status %d", resp.StatusCode)
	}
	if resp.ContentLength > c.maxBytes() {
		return nil, fmt.Errorf("npm tarball exceeds max bytes")
	}
	limited := io.LimitReader(resp.Body, c.maxBytes()+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > c.maxBytes() {
		return nil, fmt.Errorf("npm tarball exceeds max bytes")
	}
	return b, nil
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
	if !strings.EqualFold(u.Host, base.Host) {
		return fmt.Errorf("artifact url host %s not allowed", u.Host)
	}
	return nil
}

func (c Client) Observe(ctx context.Context, name, version string) (Artifact, error) {
	meta, err := c.FetchMetadata(ctx, name)
	if err != nil {
		return Artifact{}, err
	}
	v, ok := meta.Versions[version]
	if !ok {
		return Artifact{}, fmt.Errorf("npm version %q not found", version)
	}
	if v.Dist.Tarball == "" {
		return Artifact{}, fmt.Errorf("npm version %q missing tarball", version)
	}
	body, err := c.Download(ctx, v.Dist.Tarball)
	if err != nil {
		return Artifact{}, err
	}
	artifactID := "npm:" + strings.ReplaceAll(meta.Name, "/", "~") + "@" + version + ":" + filenameFromTarballURL(v.Dist.Tarball)
	verification, registry, local, err := VerifyTarballBytes(artifactID, v.Dist.Integrity, v.Dist.Shasum, body)
	if err != nil {
		return Artifact{}, err
	}
	published := time.Time{}
	if meta.Time != nil && meta.Time[version] != "" {
		published, _ = time.Parse(time.RFC3339, meta.Time[version])
	}
	return Artifact{Package: meta.Name, Version: version, Filename: filenameFromTarballURL(v.Dist.Tarball), TarballURL: v.Dist.Tarball, Integrity: v.Dist.Integrity, Shasum: v.Dist.Shasum, PublishedAt: published, RegistryHashes: registry, LocalHashes: local, Verification: verification}, nil
}
