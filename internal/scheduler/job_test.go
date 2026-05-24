package scheduler

import (
	"sync"
	"testing"
	"time"
)

func TestValidateRejectsSubMinute(t *testing.T) {
	if (ScheduledJob{Kind: "poll", Target: "npm", Cadence: time.Second}).Validate() == nil {
		t.Fatal("want err")
	}
	if (ScheduledJob{Kind: "poll", Target: "npm", Cadence: time.Minute}).Validate() != nil {
		t.Fatal("want ok")
	}
}
func TestLeaseSingleWinner(t *testing.T) {
	now := time.Unix(0, 0)
	m := NewMemoryLeases(ScheduledJob{Kind: "poll", Target: "npm", Cadence: time.Minute, NextRunAt: now})
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for _, owner := range []string{"a", "b"} {
		wg.Add(1)
		go func(o string) {
			defer wg.Done()
			if _, ok := m.Claim(now, o, time.Minute); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(owner)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins=%d", wins)
	}
}
