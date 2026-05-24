package db

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func MigrateUp(dsn string) error              { return run(dsn, ".up.sql") }
func MigrateDown(dsn string, steps int) error { return run(dsn, ".down.sql") }
func run(dsn, suffix string) error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	files, err := filepath.Glob("db/migrations/*" + suffix)
	if err != nil {
		return err
	}
	sort.Strings(files)
	if suffix == ".down.sql" {
		for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
			files[i], files[j] = files[j], files[i]
		}
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		for _, stmt := range strings.Split(string(b), ";\n") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := conn.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
		}
	}
	return nil
}
