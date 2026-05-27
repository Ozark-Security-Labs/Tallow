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

func TestSplitSQLStatementsKeepsDollarQuotedBlocks(t *testing.T) {
	stmts := splitSQLStatements("CREATE TABLE a(id int);\nDO $$\nBEGIN\nRAISE NOTICE 'x;y';\nEND $$;\nSELECT 1;")
	if len(stmts) != 3 {
		t.Fatalf("got %d statements: %#v", len(stmts), stmts)
	}
	if !strings.Contains(stmts[1], "RAISE NOTICE") || !strings.Contains(stmts[1], "END $$") {
		t.Fatalf("dollar block split incorrectly: %#v", stmts)
	}
}
