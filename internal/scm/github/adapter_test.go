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
	repo, err := adapter.ResolveRepository(context.Background(), scm.RepositoryRef{Provider: "github", Owner: "owner", Name: "repo", URL: "https://github.com/owner/repo"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.DefaultBranch != "main" || repo.Tags[0] != "v1.0.0" {
		t.Fatalf("bad repo: %+v", repo)
	}
	m, err := adapter.FetchManifest(context.Background(), repo.Ref, "package.json", "main")
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
		_, err := (&Adapter{Client: client}).ResolveRepository(context.Background(), scm.RepositoryRef{Owner: "o", Name: "r"})
		ts.Close()
		if err != want {
			t.Fatalf("status %d err %v want %v", status, err, want)
		}
	}
}
