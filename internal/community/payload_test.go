package community

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommunityPayloadEnabledAndDisabledGoldens(t *testing.T) {
	now := time.Date(2026, 5, 28, 14, 33, 9, 0, time.UTC)
	disabled, err := BuildPayload(OptIn{Enabled: false, OrganizationID: "org"}, "instance", "test", now, []BuildSignalInput{{SignalID: "S-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.SharingEnabled || len(disabled.Signals) != 0 {
		t.Fatalf("disabled=%+v", disabled)
	}
	enabled, err := BuildPayload(OptIn{Enabled: true, OrganizationID: "org"}, "instance", "test", now, []BuildSignalInput{{SignalID: "S-1", Ecosystem: "npm", PackageName: "@private/pkg", RuleID: "rule-1", SignalType: "yanked", ObservedAt: now, EvidenceDigest: "sha256:evidence", Confidence: "medium"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(enabled)
	if strings.Contains(string(b), "@private/pkg") {
		t.Fatal(string(b))
	}
	if enabled.Signals[0].ObservedAtCoarse != "2026-05-28T14:00:00Z" {
		t.Fatalf("coarse=%s", enabled.Signals[0].ObservedAtCoarse)
	}
	for _, path := range []string{"../../testdata/community-signals/enabled.golden.json", "../../testdata/community-signals/disabled.golden.json"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCommunityPayloadRejectsPrivateFields(t *testing.T) {
	_, err := BuildPayload(OptIn{Enabled: true, OrganizationID: "org"}, "instance", "test", time.Now(), []BuildSignalInput{{SignalID: "S-1", Ecosystem: "npm", PackageName: "pkg", RuleID: "rule", SignalType: "manual", ObservedAt: time.Now(), EvidenceDigest: "sha256:x", RawArtifact: "raw"}})
	if err == nil {
		t.Fatal("expected privacy rejection")
	}
	if err := ValidatePayload(Payload{Privacy: Privacy{RawArtifactsIncluded: true}}); err == nil {
		t.Fatal("expected privacy flag rejection")
	}
}
