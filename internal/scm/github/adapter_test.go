package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
)

func TestGitHubAdapterResolveAndFetchManifest(t *testing.T) {
	var sawAuth bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/repos/owner/repo":
			w.Write([]byte(`{"html_url":"https://github.com/owner/repo","default_branch":"main","private":false}`))
		case "/repos/owner/repo/tags":
			w.Write([]byte(`[{"name":"v1.0.0"}]`))
		case "/repos/owner/repo/releases":
			w.Write([]byte(`[{"tag_name":"v1.0.0"}]`))
		case "/repos/owner/repo/branches/main":
			w.Write([]byte(`{"name":"main","commit":{"sha":"abc123"}}`))
		case "/repos/owner/repo/contents/package.json":
			w.Write([]byte(`{"path":"package.json","encoding":"base64","content":"e30=","size":2}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	client := NewClient("")
	client.BaseURL = ts.URL
	adapter := &Adapter{Client: client}
	repo, err := adapter.GetRepository(context.Background(), scm.RepositoryRef{Provider: "github", Owner: "owner", Name: "repo", URL: "https://github.com/owner/repo"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.DefaultBranch != "main" || repo.Tags[0] != "v1.0.0" || repo.Releases[0] != "v1.0.0" {
		t.Fatalf("bad repo: %+v", repo)
	}
	m, err := adapter.FetchFile(context.Background(), repo.Ref, "package.json", "main", 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(m.Content) != "{}" || sawAuth {
		t.Fatalf("manifest/auth mismatch: %+v auth=%v", m, sawAuth)
	}
}
func TestGitHubAdapterHandlesMissingRateLimitedAndPrivate(t *testing.T) {
	for status, want := range map[int]error{404: scm.ErrNotFound, 401: scm.ErrUnauthorized, 403: scm.ErrRateLimited} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status == 403 {
				w.Header().Set("X-RateLimit-Remaining", "0")
			}
			w.WriteHeader(status)
		}))
		client := NewClient("")
		client.BaseURL = ts.URL
		_, err := (&Adapter{Client: client}).GetRepository(context.Background(), scm.RepositoryRef{Owner: "o", Name: "r"})
		ts.Close()
		if err != want {
			t.Fatalf("status %d err %v want %v", status, err, want)
		}
	}
}

func TestGitHubAdapterFetchFileEscapesRevision(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "ref=release%2F1%3Fx%3D1" {
			t.Fatalf("raw query not escaped: %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"path":"dir/package.json","encoding":"base64","content":"e30=","size":2}`))
	}))
	defer ts.Close()
	client := NewClient("")
	client.BaseURL = ts.URL
	_, err := (&Adapter{Client: client}).FetchFile(context.Background(), scm.RepositoryRef{Owner: "owner", Name: "repo"}, "dir/package.json", "release/1?x=1", 10)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGitHubAdapterRejectsDotSegmentPaths(t *testing.T) {
	client := NewClient("")
	_, err := (&Adapter{Client: client}).FetchFile(context.Background(), scm.RepositoryRef{Owner: "owner", Name: "repo"}, "../package.json", "main", 10)
	if err != scm.ErrInvalidResponse {
		t.Fatalf("err = %v", err)
	}
}
