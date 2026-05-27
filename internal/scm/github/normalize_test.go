package github

import "testing"

func TestNormalizeRepositoryURL(t *testing.T) {
	for _, raw := range []string{"https://github.com/Owner/Repo", "git+https://github.com/Owner/Repo.git", "git@github.com:Owner/Repo.git"} {
		ref, ok := NormalizeRepositoryURL(raw)
		if !ok {
			t.Fatalf("not normalized: %s", raw)
		}
		if ref.Owner != "owner" || ref.Name != "repo" || ref.URL != "https://github.com/owner/repo" {
			t.Fatalf("bad ref: %+v", ref)
		}
	}
}
func TestClaimsFromPackageMetadata(t *testing.T) {
	claims := ClaimsFromPackageMetadata(PackageMetadata{Ecosystem: "npm", RepositoryURL: "https://github.com/O/R", ProjectURLs: map[string]string{"Source": "https://github.com/O/R"}})
	if len(claims) != 1 || claims[0].Ref.Name != "r" {
		t.Fatalf("bad claims: %+v", claims)
	}
}
