package correlation

import "github.com/Ozark-Security-Labs/Tallow/internal/scm"

type Confidence string

const (
	ConfidenceExactMetadata      Confidence = "exact_metadata"
	ConfidenceReleaseTagMatch    Confidence = "release_tag_match"
	ConfidenceRepositoryMetadata Confidence = "repository_metadata"
	ConfidenceManifestObserved   Confidence = "manifest_observed"
	ConfidenceInferredName       Confidence = "inferred_name"
	ConfidenceConflicting        Confidence = "conflicting"
	ConfidenceUnknown            Confidence = "unknown"
)

type Evidence struct {
	Source string `json:"source"`
	URL    string `json:"url,omitempty"`
	Detail string `json:"detail,omitempty"`
}
type PackageVersion struct {
	Ecosystem string
	Name      string
	Version   string
}
type Candidate struct {
	Ref      scm.RepositoryRef
	Revision string
	Evidence Evidence
}
type Decision struct {
	Package     PackageVersion
	Ref         scm.RepositoryRef
	Revision    string
	Confidence  Confidence
	Evidence    []Evidence
	Explanation string
	Ambiguous   bool
}
