//go:build integration

package scheduler

import "testing"

func TestIntegrationPlanned(t *testing.T) {
	t.Skip("DB-backed two-worker lease integration requires a live Postgres service and will be added with the scheduler persistence milestone")
}
