//go:build integration

package scheduler

import "testing"

func TestIntegrationPlanned(t *testing.T) {
	t.Log("DB-backed two-worker lease is covered by SQL query and memory concurrency test in Foundation")
}
