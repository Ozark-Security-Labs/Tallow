package scm_test

import (
	"context"
	"encoding/json"
	adapterscm "github.com/Ozark-Security-Labs/Tallow/internal/adapters/scm"
	"github.com/Ozark-Security-Labs/Tallow/internal/adapters/scm/fake"
	githubadapter "github.com/Ozark-Security-Labs/Tallow/internal/adapters/scm/github"
	"os"
	"testing"
)

func TestSCMAdapterContracts(t *testing.T) {
	adapters := []adapterscm.Adapter{fake.Adapter{}, githubadapter.Adapter{}}
	for _, a := range adapters {
		if a.Provider() == "" {
			t.Fatal("missing provider")
		}
	}
	repo, _ := (fake.Adapter{}).NormalizeRepository("https://github.com/owner/repo")
	meta, err := (fake.Adapter{}).FetchRepository(context.Background(), repo)
	if err != nil || meta.DefaultBranch != "main" {
		t.Fatalf("meta=%+v err=%v", meta, err)
	}
}
func TestSCMFixtureRoundTrip(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/adapter-fixtures/scm/repository.github.json")
	if err != nil {
		t.Fatal(err)
	}
	var v adapterscm.RepositoryMetadata
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Identity.Provider != adapterscm.ProviderGitHub {
		t.Fatalf("fixture=%+v", v)
	}
}
