package scheduler

import (
	"testing"
	"time"
)

func TestPollingTierNextRunAndJitterBounds(t *testing.T) {
	tiers := DefaultPollingTiers()
	now := time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	hot := tiers.NextRun(now, "pkg", PriorityHot)
	if hot.Before(now.Add(5*time.Minute)) || hot.After(now.Add(5*time.Minute+30*time.Second)) {
		t.Fatalf("hot out of bounds %s", hot)
	}
	if tiers.NextRun(now, "pkg", PriorityWarm).Before(now.Add(30 * time.Minute)) {
		t.Fatal("warm interval")
	}
	if tiers.NextRun(now, "pkg", PriorityCold).Before(now.Add(12 * time.Hour)) {
		t.Fatal("cold interval")
	}
}
func TestPollingTierPrioritySignals(t *testing.T) {
	if PriorityFor(PackageSignals{DirectDependency: true}) != PriorityHot || PriorityFor(PackageSignals{ProductionDependency: true}) != PriorityHot || PriorityFor(PackageSignals{HighRisk: true}) != PriorityHot {
		t.Fatal("hot signal failed")
	}
	if PriorityFor(PackageSignals{}) != PriorityWarm {
		t.Fatal("default warm")
	}
}
func TestBurstSchedule(t *testing.T) {
	rel := time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	got := DefaultPollingTiers().BurstRuns(rel)
	want := []time.Duration{5 * time.Minute, 30 * time.Minute, 6 * time.Hour, 24 * time.Hour}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i, w := range want {
		if !got[i].Equal(rel.Add(w)) {
			t.Fatalf("burst %d got %s", i, got[i])
		}
	}
}
