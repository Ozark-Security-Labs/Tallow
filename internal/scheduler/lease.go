package scheduler

import (
	"sync"
	"time"
)

type MemoryLeases struct {
	mu   sync.Mutex
	jobs map[string]ScheduledJob
}

func NewMemoryLeases(js ...ScheduledJob) *MemoryLeases {
	m := &MemoryLeases{jobs: map[string]ScheduledJob{}}
	for _, j := range js {
		m.jobs[j.Kind+"/"+j.Target] = j
	}
	return m
}
func (m *MemoryLeases) Claim(now time.Time, owner string, ttl time.Duration) (ScheduledJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, j := range m.jobs {
		if !j.NextRunAt.After(now) && (j.LeaseOwner == "" || j.LeaseUntil.Before(now)) {
			j.LeaseOwner = owner
			j.LeaseUntil = now.Add(ttl)
			m.jobs[k] = j
			return j, true
		}
	}
	return ScheduledJob{}, false
}
func (m *MemoryLeases) Release(j ScheduledJob, owner string, next time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := j.Kind + "/" + j.Target
	cur, ok := m.jobs[k]
	if !ok || cur.LeaseOwner != owner {
		return false
	}
	cur.LeaseOwner = ""
	cur.LeaseUntil = time.Time{}
	cur.NextRunAt = next
	m.jobs[k] = cur
	return true
}
