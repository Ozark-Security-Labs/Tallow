//go:build integration

package db

import (
	"os"
	"testing"
)

func TestMigrateUpIntegration(t *testing.T) {
	dsn := os.Getenv("TALLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable"
	}
	if err := MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
	if err := MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
}
