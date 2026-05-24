package scheduler

import (
	"github.com/Ozark-Security-Labs/Tallow/internal/tallowerr"
	"time"
)

type ScheduledJob struct {
	Kind       string
	Target     string
	Cadence    time.Duration
	NextRunAt  time.Time
	LeaseOwner string
	LeaseUntil time.Time
}

func (j ScheduledJob) Validate() error {
	if j.Kind == "" || j.Target == "" {
		return tallowerr.New(tallowerr.CodeValidation, "job kind and target required")
	}
	if j.Cadence < time.Minute {
		return tallowerr.New(tallowerr.CodeValidation, "cadence below one minute")
	}
	return nil
}
func (j ScheduledJob) NextAfter(t time.Time) time.Time { return t.Add(j.Cadence) }
func DeterministicJitter(key string, max time.Duration) time.Duration {
	var sum int64
	for _, r := range key {
		sum += int64(r)
	}
	if max <= 0 {
		return 0
	}
	return time.Duration(sum % int64(max))
}
