package scm

import "time"

type RepositoryRef struct {
	Provider string
	Owner    string
	Name     string
	URL      string
}
type Repository struct {
	Ref           RepositoryRef
	DefaultBranch string
	Visibility    string
	Tags          []string
	Releases      []string
}
type Revision struct {
	SHA        string
	Branch     string
	Tag        string
	ObservedAt time.Time
}
type Manifest struct {
	Path     string
	Revision string
	Content  []byte
	Size     int64
}
type MetadataClaim struct {
	Source   string
	URL      string
	Ref      RepositoryRef
	Evidence string
}
