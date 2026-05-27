package github

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
)

type Adapter struct{ Client *Client }

func New(token string) *Adapter { return &Adapter{Client: NewClient(token)} }

type repoResp struct {
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
}
type tagResp struct {
	Name string `json:"name"`
}
type contentResp struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
}

func (a *Adapter) ResolveRepository(ctx context.Context, ref scm.RepositoryRef) (scm.Repository, error) {
	var rr repoResp
	if err := a.Client.get(ctx, "/repos/"+ref.Owner+"/"+ref.Name, &rr); err != nil {
		return scm.Repository{}, err
	}
	var tags []tagResp
	_ = a.Client.get(ctx, "/repos/"+ref.Owner+"/"+ref.Name+"/tags", &tags)
	names := make([]string, 0, len(tags))
	for _, t := range tags {
		names = append(names, t.Name)
	}
	vis := "public"
	if rr.Private {
		vis = "private"
	}
	if rr.HTMLURL != "" {
		ref.URL = rr.HTMLURL
	}
	return scm.Repository{Ref: ref, DefaultBranch: rr.DefaultBranch, Visibility: vis, Tags: names}, nil
}

func (a *Adapter) FetchManifest(ctx context.Context, ref scm.RepositoryRef, path, revision string) (scm.Manifest, error) {
	url := "/repos/" + ref.Owner + "/" + ref.Name + "/contents/" + strings.TrimPrefix(path, "/")
	if revision != "" {
		url += "?ref=" + revision
	}
	var cr contentResp
	if err := a.Client.get(ctx, url, &cr); err != nil {
		return scm.Manifest{}, err
	}
	content := []byte(cr.Content)
	if cr.Encoding == "base64" {
		b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cr.Content, "\n", ""))
		if err == nil {
			content = b
		}
	}
	return scm.Manifest{Path: cr.Path, Revision: revision, Content: content, Size: cr.Size}, nil
}

func (a *Adapter) RevisionMetadata(ctx context.Context, ref scm.RepositoryRef, revision string) (scm.Revision, error) {
	return scm.Revision{Branch: revision}, nil
}

func (a *Adapter) PollRepositories(context.Context, scm.RepositoryCursor) (scm.RepositoryPage, error) {
	return scm.RepositoryPage{}, nil
}
