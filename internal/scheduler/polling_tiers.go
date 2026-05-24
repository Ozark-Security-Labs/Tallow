package scheduler

import "time"

type PollingTiers struct {
	Hot    time.Duration
	Warm   time.Duration
	Cold   time.Duration
	Jitter time.Duration
	Burst  []time.Duration
}

func DefaultPollingTiers() PollingTiers {
	return PollingTiers{Hot: 5 * time.Minute, Warm: 30 * time.Minute, Cold: 12 * time.Hour, Jitter: 30 * time.Second, Burst: []time.Duration{5 * time.Minute, 30 * time.Minute, 6 * time.Hour, 24 * time.Hour}}
}
func (p PollingTiers) Interval(priority PackagePriority) time.Duration {
	d := DefaultPollingTiers()
	if p.Hot == 0 {
		p.Hot = d.Hot
	}
	if p.Warm == 0 {
		p.Warm = d.Warm
	}
	if p.Cold == 0 {
		p.Cold = d.Cold
	}
	switch priority {
	case PriorityHot:
		return p.Hot
	case PriorityCold:
		return p.Cold
	default:
		return p.Warm
	}
}
func (p PollingTiers) NextRun(now time.Time, key string, priority PackagePriority) time.Time {
	d := DefaultPollingTiers()
	if p.Jitter == 0 {
		p.Jitter = d.Jitter
	}
	return now.Add(p.Interval(priority)).Add(DeterministicJitter(key, p.Jitter))
}
func (p PollingTiers) BurstRuns(release time.Time) []time.Time {
	d := DefaultPollingTiers()
	if len(p.Burst) == 0 {
		p.Burst = d.Burst
	}
	out := make([]time.Time, len(p.Burst))
	for i, b := range p.Burst {
		out[i] = release.Add(b)
	}
	return out
}
