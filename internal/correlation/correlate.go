package correlation

import "sort"

func Correlate(pkg PackageVersion, candidates []Candidate) Decision {
	if len(candidates) == 0 {
		return Decision{Package: pkg, Confidence: ConfidenceUnknown, Score: 0, Explanation: "no source repository evidence"}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Ref.URL < candidates[j].Ref.URL })
	first := candidates[0]
	evidence := make([]Evidence, 0, len(candidates))
	urls := map[string]bool{}
	conflicting := []string{}
	for _, c := range candidates {
		evidence = append(evidence, c.Evidence)
		if !urls[c.Ref.URL] {
			conflicting = append(conflicting, c.Ref.URL)
		}
		urls[c.Ref.URL] = true
	}
	if len(urls) > 1 {
		return Decision{Package: pkg, Confidence: ConfidenceConflicting, Score: 10, ConflictingSourceIDs: conflicting, Evidence: evidence, Explanation: "multiple conflicting repository candidates", Ambiguous: true}
	}
	conf := ConfidenceRepositoryMetadata
	score := 70
	if first.Evidence.Source == string(EvidenceExactMetadata) {
		conf = ConfidenceExactMetadata
		score = 100
	} else if first.Revision != "" {
		conf = ConfidenceReleaseTagMatch
		score = 90
	}
	return Decision{Package: pkg, Ref: first.Ref, Revision: first.Revision, Confidence: conf, Score: score, Evidence: evidence, Explanation: "repository metadata matched package source"}
}
