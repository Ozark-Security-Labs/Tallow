package artifacts

import "testing"

func TestVerificationPolicyDefaultFailClosed(t *testing.T) {
	p := DefaultVerificationPolicy()
	verified := p.Decide(StatusVerified)
	if !verified.MayUnpack || !verified.MayAnalyze || verified.Quarantine {
		t.Fatalf("verified should proceed: %#v", verified)
	}
	missing := p.Decide(StatusUnverifiedMissingRegistryHash)
	if missing.MayAnalyze || missing.MayUnpack {
		t.Fatalf("missing hash should fail closed by default: %#v", missing)
	}
	mismatch := p.Decide(StatusMismatch)
	if mismatch.MayAnalyze || mismatch.MayUnpack || !mismatch.Quarantine || !mismatch.CriticalFinding {
		t.Fatalf("mismatch should quarantine critical and block dispatch: %#v", mismatch)
	}
}

func TestVerificationPolicyAllowsExplicitUnverifiedHandling(t *testing.T) {
	p := DefaultVerificationPolicy()
	p.AllowUnverifiedUnpack = true
	p.AllowUnverifiedAnalysis = true
	got := p.Decide(StatusUnverifiedMissingRegistryHash)
	if !got.MayUnpack || !got.MayAnalyze {
		t.Fatalf("explicit opt-in should allow missing hash: %#v", got)
	}
}
