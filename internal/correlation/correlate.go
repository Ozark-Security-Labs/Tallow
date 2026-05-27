package correlation

import "sort"

func Correlate(pkg PackageVersion, candidates []Candidate) Decision {
	if len(candidates) == 0 {
		return Decision{Package: pkg, Confidence: ConfidenceUnknown, Explanation: "no source repository evidence"}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Ref.URL < candidates[j].Ref.URL })
	first := candidates[0]
	evidence := make([]Evidence, 0, len(candidates))
	urls := map[string]bool{}
	for _, c := range candidates {
		evidence = append(evidence, c.Evidence)
		urls[c.Ref.URL] = true
	}
	if len(urls) > 1 {
		return Decision{Package: pkg, Confidence: ConfidenceConflicting, Evidence: evidence, Explanation: "multiple conflicting repository candidates", Ambiguous: true}
	}
	conf := ConfidenceRepositoryMetadata
	if first.Revision != "" {
		conf = ConfidenceReleaseTagMatch
	}
	return Decision{Package: pkg, Ref: first.Ref, Revision: first.Revision, Confidence: conf, Evidence: evidence, Explanation: "repository metadata matched package source"}
}
