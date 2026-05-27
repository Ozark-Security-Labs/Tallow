package github

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
)

var scpLike = regexp.MustCompile(`^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$`)

func NormalizeRepositoryURL(raw string) (scm.RepositoryRef, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return scm.RepositoryRef{}, false
	}
	if m := scpLike.FindStringSubmatch(raw); m != nil {
		return ref(m[1], m[2]), true
	}
	raw = strings.TrimPrefix(raw, "git+")
	u, err := url.Parse(raw)
	if err != nil {
		return scm.RepositoryRef{}, false
	}
	if u.Host != "github.com" && u.Host != "www.github.com" {
		return scm.RepositoryRef{}, false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return scm.RepositoryRef{}, false
	}
	name := strings.TrimSuffix(parts[1], ".git")
	if !validRepoPart(parts[0]) || !validRepoPart(name) {
		return scm.RepositoryRef{}, false
	}
	return ref(parts[0], name), true
}
func ref(owner, name string) scm.RepositoryRef {
	owner = strings.ToLower(owner)
	name = strings.ToLower(name)
	return scm.RepositoryRef{Provider: "github", Owner: owner, Name: name, URL: "https://github.com/" + owner + "/" + name}
}

func validRepoPart(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.Contains(s, "/")
}
