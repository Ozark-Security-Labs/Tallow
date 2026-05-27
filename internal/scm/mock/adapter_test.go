package mock

import (
	"context"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
)

func TestMockAdapterImplementsSCMInterface(t *testing.T) {
	var _ scm.Adapter = Adapter{}
	ref := scm.RepositoryRef{Provider: "github", Owner: "o", Name: "r", URL: "https://github.com/o/r"}
	adapter := Adapter{Repositories: map[string]scm.Repository{ref.URL: {Ref: ref, DefaultBranch: "main"}}, Manifests: map[string]scm.Manifest{ref.URL + ":main:package.json": {Path: "package.json", Revision: "main", Content: []byte("{}")}}, Revisions: map[string]scm.Revision{ref.URL + ":main": {Branch: "main", SHA: "abc"}}, Page: scm.RepositoryPage{Repositories: []scm.RepositoryRef{ref}}}
	if repo, err := adapter.GetRepository(context.Background(), ref); err != nil || repo.DefaultBranch != "main" {
		t.Fatalf("repo %+v err %v", repo, err)
	}
	if manifest, err := adapter.FetchFile(context.Background(), ref, "package.json", "main", 10); err != nil || string(manifest.Content) != "{}" {
		t.Fatalf("manifest %+v err %v", manifest, err)
	}
	if rev, err := adapter.GetRevision(context.Background(), ref, "main"); err != nil || rev.SHA != "abc" {
		t.Fatalf("revision %+v err %v", rev, err)
	}
	if page, err := adapter.Poll(context.Background(), scm.RepositoryCursor{}); err != nil || len(page.Repositories) != 1 {
		t.Fatalf("page %+v err %v", page, err)
	}
}
