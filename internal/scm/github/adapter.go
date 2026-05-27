package github

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
)

var _ scm.Adapter = (*Adapter)(nil)

type Adapter struct{ Client *Client }

func New(token string) *Adapter     { return &Adapter{Client: NewClient(token)} }
func (a *Adapter) Provider() string { return "github" }

type repoResp struct {
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
}
type tagResp struct {
	Name string `json:"name"`
}
type releaseResp struct {
	TagName string `json:"tag_name"`
}
type branchResp struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}
type commitResp struct {
	SHA string `json:"sha"`
}
type contentResp struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
}

func (a *Adapter) ResolveRepository(_ context.Context, claim scm.RepositoryClaim) (scm.RepositoryRef, error) {
	if claim.URL != "" {
		if ref, ok := NormalizeRepositoryURL(claim.URL); ok {
			return ref, nil
		}
	}
	if claim.Provider == "github" && claim.Owner != "" && claim.Name != "" {
		return scm.RepositoryRef{Provider: "github", Owner: strings.ToLower(claim.Owner), Name: strings.ToLower(claim.Name), URL: "https://github.com/" + strings.ToLower(claim.Owner) + "/" + strings.ToLower(claim.Name)}, nil
	}
	return scm.RepositoryRef{}, scm.ErrNotFound
}

func (a *Adapter) GetRepository(ctx context.Context, ref scm.RepositoryRef) (scm.Repository, error) {
	var rr repoResp
	if err := a.Client.get(ctx, repoPath(ref), &rr); err != nil {
		return scm.Repository{}, err
	}
	var tags []tagResp
	_ = a.Client.get(ctx, repoPath(ref)+"/tags", &tags)
	var releases []releaseResp
	_ = a.Client.get(ctx, repoPath(ref)+"/releases", &releases)
	tagNames := make([]string, 0, len(tags))
	for _, t := range tags {
		tagNames = append(tagNames, t.Name)
	}
	releaseNames := make([]string, 0, len(releases))
	for _, r := range releases {
		releaseNames = append(releaseNames, r.TagName)
	}
	vis := "public"
	if rr.Private {
		vis = "private"
	}
	if rr.HTMLURL != "" {
		ref.URL = rr.HTMLURL
	}
	return scm.Repository{Ref: ref, DefaultBranch: rr.DefaultBranch, Visibility: vis, Tags: tagNames, Releases: releaseNames}, nil
}

func (a *Adapter) ResolveRepositoryLegacy(ctx context.Context, ref scm.RepositoryRef) (scm.Repository, error) {
	return a.GetRepository(ctx, ref)
}
func (a *Adapter) ResolveRepositoryMetadata(ctx context.Context, ref scm.RepositoryRef) (scm.Repository, error) {
	return a.GetRepository(ctx, ref)
}

func (a *Adapter) GetDefaultBranch(ctx context.Context, ref scm.RepositoryRef) (scm.Revision, error) {
	repo, err := a.GetRepository(ctx, ref)
	if err != nil {
		return scm.Revision{}, err
	}
	return a.GetRevision(ctx, ref, repo.DefaultBranch)
}

func (a *Adapter) ListRepositoryManifests(ctx context.Context, ref scm.RepositoryRef, revision string) ([]scm.Manifest, error) {
	candidates := []string{"package.json", "package-lock.json", "requirements.txt", "pyproject.toml", "poetry.lock"}
	out := make([]scm.Manifest, 0, len(candidates))
	for _, path := range candidates {
		m, err := a.FetchFile(ctx, ref, path, revision, 1<<20)
		if err == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

func (a *Adapter) FetchFile(ctx context.Context, ref scm.RepositoryRef, path, revision string, maxBytes int64) (scm.Manifest, error) {
	escaped, err := escapeContentPath(path)
	if err != nil {
		return scm.Manifest{}, err
	}
	u := repoPath(ref) + "/contents/" + escaped
	if revision != "" {
		u += "?ref=" + url.QueryEscape(revision)
	}
	var cr contentResp
	if err := a.Client.get(ctx, u, &cr); err != nil {
		return scm.Manifest{}, err
	}
	if maxBytes > 0 && cr.Size > maxBytes {
		return scm.Manifest{}, scm.ErrInvalidResponse
	}
	content := []byte(cr.Content)
	if cr.Encoding == "base64" {
		b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cr.Content, "\n", ""))
		if err == nil {
			content = b
		}
	}
	if maxBytes > 0 && int64(len(content)) > maxBytes {
		return scm.Manifest{}, scm.ErrInvalidResponse
	}
	return scm.Manifest{Path: cr.Path, Revision: revision, Content: content, Size: cr.Size}, nil
}

func (a *Adapter) FetchManifest(ctx context.Context, ref scm.RepositoryRef, path, revision string) (scm.Manifest, error) {
	return a.FetchFile(ctx, ref, path, revision, 1<<20)
}

func (a *Adapter) GetRevision(ctx context.Context, ref scm.RepositoryRef, revision string) (scm.Revision, error) {
	if revision == "" {
		return scm.Revision{}, scm.ErrNotFound
	}
	var br branchResp
	if err := a.Client.get(ctx, repoPath(ref)+"/branches/"+url.PathEscape(revision), &br); err == nil {
		return scm.Revision{SHA: br.Commit.SHA, Branch: br.Name, ObservedAt: time.Now().UTC()}, nil
	}
	var cm commitResp
	if err := a.Client.get(ctx, repoPath(ref)+"/commits/"+url.PathEscape(revision), &cm); err != nil {
		return scm.Revision{}, err
	}
	return scm.Revision{SHA: cm.SHA, Tag: revision, ObservedAt: time.Now().UTC()}, nil
}

func (a *Adapter) RevisionMetadata(ctx context.Context, ref scm.RepositoryRef, revision string) (scm.Revision, error) {
	return a.GetRevision(ctx, ref, revision)
}
func (a *Adapter) Poll(context.Context, scm.RepositoryCursor) (scm.RepositoryPage, error) {
	return scm.RepositoryPage{}, nil
}
func (a *Adapter) PollRepositories(ctx context.Context, cursor scm.RepositoryCursor) (scm.RepositoryPage, error) {
	return a.Poll(ctx, cursor)
}
func repoPath(ref scm.RepositoryRef) string {
	return "/repos/" + url.PathEscape(ref.Owner) + "/" + url.PathEscape(ref.Name)
}
func escapeContentPath(path string) (string, error) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if p == "." || p == ".." {
			return "", scm.ErrInvalidResponse
		}
		out = append(out, url.PathEscape(p))
	}
	if len(out) == 0 {
		return "", scm.ErrInvalidResponse
	}
	return strings.Join(out, "/"), nil
}
