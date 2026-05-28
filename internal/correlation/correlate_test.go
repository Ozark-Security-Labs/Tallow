package correlation

import (
	"github.com/Ozark-Security-Labs/Tallow/internal/scm"
	"testing"
)

func TestCorrelateExactMissingMultipleConflictingEvidence(t *testing.T) {
	pkg := PackageVersion{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}
	missing := Correlate(pkg, nil)
	if missing.Confidence != ConfidenceUnknown {
		t.Fatalf("missing = %+v", missing)
	}
	ref := scm.RepositoryRef{Provider: "github", Owner: "o", Name: "r", URL: "https://github.com/o/r"}
	exact := Correlate(pkg, []Candidate{{Ref: ref, Revision: "v1.0.0", Evidence: Evidence{Source: string(EvidenceExactMetadata), URL: ref.URL}}})
	if exact.Confidence != ConfidenceExactMetadata || exact.Score != 100 || exact.Ambiguous {
		t.Fatalf("exact = %+v", exact)
	}
	conflict := Correlate(pkg, []Candidate{{Ref: ref, Evidence: Evidence{Source: "repository", URL: ref.URL}}, {Ref: scm.RepositoryRef{Provider: "github", URL: "https://github.com/o/other"}, Evidence: Evidence{Source: "homepage", URL: "https://github.com/o/other"}}})
	if conflict.Confidence != ConfidenceConflicting || !conflict.Ambiguous {
		t.Fatalf("conflict = %+v", conflict)
	}
}

func TestCorrelateReleaseTagMatch(t *testing.T) {
	pkg := PackageVersion{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}
	ref := scm.RepositoryRef{Provider: "github", Owner: "o", Name: "r", URL: "https://github.com/o/r"}
	decision := Correlate(pkg, []Candidate{{Ref: ref, Revision: "v1.0.0", Evidence: Evidence{Source: "repository", URL: ref.URL}}})
	if decision.Confidence != ConfidenceReleaseTagMatch {
		t.Fatalf("decision = %+v", decision)
	}
}
