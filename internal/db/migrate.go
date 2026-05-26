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

func MigrateUp(dsn string) error              { return run(dsn, ".up.sql", 0) }
func MigrateDown(dsn string, steps int) error { return run(dsn, ".down.sql", steps) }
func run(dsn, suffix string, steps int) error {
	files, err := filepath.Glob("db/migrations/*" + suffix)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no migration files found for suffix %s", suffix)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	sort.Strings(files)
	if suffix == ".down.sql" {
		for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
			files[i], files[j] = files[j], files[i]
		}
		if steps > 0 && steps < len(files) {
			files = files[:steps]
		}
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		for _, stmt := range splitSQLStatements(string(b)) {
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

func splitSQLStatements(sql string) []string {
	var statements []string
	var current strings.Builder
	inSingleQuote := false
	dollarTag := ""
	for i := 0; i < len(sql); i++ {
		if dollarTag != "" {
			if strings.HasPrefix(sql[i:], dollarTag) {
				current.WriteString(dollarTag)
				i += len(dollarTag) - 1
				dollarTag = ""
				continue
			}
			current.WriteByte(sql[i])
			continue
		}
		if !inSingleQuote && sql[i] == '$' {
			if tag, ok := readDollarTag(sql[i:]); ok {
				current.WriteString(tag)
				i += len(tag) - 1
				dollarTag = tag
				continue
			}
		}
		if sql[i] == '\'' {
			inSingleQuote = !inSingleQuote
		}
		if sql[i] == ';' && !inSingleQuote {
			statements = append(statements, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(sql[i])
	}
	if strings.TrimSpace(current.String()) != "" {
		statements = append(statements, current.String())
	}
	return statements
}

func readDollarTag(sql string) (string, bool) {
	if len(sql) < 2 || sql[0] != '$' {
		return "", false
	}
	for i := 1; i < len(sql); i++ {
		if sql[i] == '$' {
			return sql[:i+1], true
		}
		if (sql[i] < 'A' || sql[i] > 'Z') &&
			(sql[i] < 'a' || sql[i] > 'z') &&
			(sql[i] < '0' || sql[i] > '9') &&
			sql[i] != '_' {
			return "", false
		}
	}
	return "", false
}
