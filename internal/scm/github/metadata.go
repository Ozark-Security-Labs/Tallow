package github

import "github.com/Ozark-Security-Labs/Tallow/internal/scm"

type PackageMetadata struct {
	Ecosystem     string
	RepositoryURL string
	HomepageURL   string
	ProjectURLs   map[string]string
}

func ClaimsFromPackageMetadata(meta PackageMetadata) []scm.MetadataClaim {
	var out []scm.MetadataClaim
	candidates := []struct{ source, url string }{{"repository", meta.RepositoryURL}, {"homepage", meta.HomepageURL}}
	keys := []string{"Source", "Source Code", "Repository", "Homepage"}
	for _, k := range keys {
		if meta.ProjectURLs != nil {
			candidates = append(candidates, struct{ source, url string }{"project_urls." + k, meta.ProjectURLs[k]})
		}
	}
	seen := map[string]bool{}
	for _, c := range candidates {
		if c.url == "" || seen[c.url] {
			continue
		}
		seen[c.url] = true
		if r, ok := NormalizeRepositoryURL(c.url); ok {
			out = append(out, scm.MetadataClaim{Source: c.source, URL: c.url, Ref: r, Evidence: meta.Ecosystem + ":" + c.source})
		}
	}
	return out
}
