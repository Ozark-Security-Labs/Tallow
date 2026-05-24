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

func (c Client) FetchMetadata(ctx context.Context, project string) (Metadata, error) {
	u := c.BaseURL + "/pypi/" + url.PathEscape(project) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Metadata{}, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("pypi metadata status %d", resp.StatusCode)
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
		return nil, fmt.Errorf("pypi artifact status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
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
		out = append(out, Artifact{Project: meta.Info.Name, Version: version, Filename: f.Filename, Kind: ArtifactKind(f.PackageType), URL: f.URL, Yanked: f.Yanked, YankedReason: f.YankedReason, UploadedAt: uploaded, RegistryHashes: registry, LocalHashes: local, Verification: verification})
	}
	return out, nil
}
