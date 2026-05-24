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

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string, hc *http.Client) Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: hc}
}

func (c Client) FetchMetadata(ctx context.Context, name string) (Metadata, error) {
	pathName := url.PathEscape(name)
	pathName = strings.ReplaceAll(pathName, "%2F", "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/"+pathName, nil)
	if err != nil {
		return Metadata{}, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("npm metadata status %d", resp.StatusCode)
	}
	var meta Metadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return Metadata{}, err
	}
	return meta, nil
}

func (c Client) Download(ctx context.Context, rawurl string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm tarball status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
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
	artifactID := "npm:" + meta.Name + "@" + version + ":" + filenameFromTarballURL(v.Dist.Tarball)
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
