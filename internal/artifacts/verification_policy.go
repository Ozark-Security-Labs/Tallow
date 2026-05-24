package artifacts

type VerificationPolicy struct {
	AllowUnverifiedUnpack    bool
	AllowUnverifiedAnalysis  bool
	QuarantineMismatches     bool
	EmitCriticalOnMismatch   bool
	DispatchAnalyzerOnVerify bool
}

type PolicyDecision struct {
	MayUnpack       bool
	MayAnalyze      bool
	Quarantine      bool
	CriticalFinding bool
	EventType       string
	Reason          string
}

func DefaultVerificationPolicy() VerificationPolicy {
	return VerificationPolicy{QuarantineMismatches: true, EmitCriticalOnMismatch: true, DispatchAnalyzerOnVerify: true}
}

func (p VerificationPolicy) Decide(status VerificationStatus) PolicyDecision {
	switch status {
	case StatusVerified:
		return PolicyDecision{MayUnpack: true, MayAnalyze: p.DispatchAnalyzerOnVerify, EventType: "artifact.hash.verified", Reason: "registry hash matched local digest"}
	case StatusUnverifiedMissingRegistryHash:
		return PolicyDecision{MayUnpack: p.AllowUnverifiedUnpack, MayAnalyze: p.AllowUnverifiedAnalysis, EventType: "artifact.hash.unverified", Reason: "registry did not provide a supported hash"}
	case StatusMismatch:
		return PolicyDecision{MayUnpack: false, MayAnalyze: false, Quarantine: p.QuarantineMismatches, CriticalFinding: p.EmitCriticalOnMismatch, EventType: "artifact.hash.mismatch", Reason: "registry hash mismatch"}
	default:
		return PolicyDecision{MayUnpack: false, MayAnalyze: false, Quarantine: true, CriticalFinding: true, EventType: "artifact.hash.failed", Reason: "unknown verification status"}
	}
}
