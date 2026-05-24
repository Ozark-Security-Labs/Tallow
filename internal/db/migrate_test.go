package db

import (
	"os"
	"strings"
	"testing"
)

func TestPackageCompiles(t *testing.T) { _ = MigrateUp }

func TestMigrateErrorsWhenNoFilesFound(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	err = MigrateUp("postgres://invalid")
	if err == nil || !strings.Contains(err.Error(), "no migration files found") {
		t.Fatalf("want missing migrations error, got %v", err)
	}
}
