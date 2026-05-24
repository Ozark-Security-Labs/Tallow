package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/db"
	"github.com/Ozark-Security-Labs/Tallow/internal/version"
	"io"
	"strings"
)

const (
	ExitOK             = 0
	ExitGeneral        = 1
	ExitUsage          = 2
	ExitConfig         = 3
	ExitDependency     = 4
	ExitNotImplemented = 10
)

type App struct{ Out, Err io.Writer }

func (a App) Run(args []string) int {
	if a.Out == nil {
		a.Out = io.Discard
	}
	if a.Err == nil {
		a.Err = io.Discard
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		a.help()
		return ExitOK
	}
	switch args[0] {
	case "version":
		return a.version(args[1:])
	case "server":
		fmt.Fprintln(a.Out, "run `tallow-api` or `tallow server` to start the API")
		return ExitOK
	case "observe", "analyze":
		fmt.Fprintf(a.Err, "%s is not implemented in Foundation and does not fetch or execute packages\n", args[0])
		return ExitNotImplemented
	case "db":
		return a.db(args[1:])
	default:
		fmt.Fprintf(a.Err, "unknown command %q\n", args[0])
		return ExitUsage
	}
}
func (a App) help() {
	fmt.Fprintln(a.Out, "tallow commands: version, server, observe, analyze, db migrate")
}
func (a App) version(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	js := fs.Bool("json", false, "json output")
	if fs.Parse(args) != nil {
		return ExitUsage
	}
	if *js {
		_ = json.NewEncoder(a.Out).Encode(version.Info())
		return ExitOK
	}
	fmt.Fprintln(a.Out, version.Info().Version)
	return ExitOK
}
func (a App) db(args []string) int {
	if len(args) == 0 || args[0] != "migrate" {
		fmt.Fprintln(a.Err, "usage: tallow db migrate [--config path]")
		return ExitUsage
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	cfgPath := fs.String("config", "", "config path (reserved)")
	if fs.Parse(args[1:]) != nil {
		return ExitUsage
	}
	_ = *cfgPath
	cfg, err := config.LoadFromEnvironment()
	if err != nil {
		fmt.Fprintln(a.Err, err)
		return ExitConfig
	}
	if err := db.MigrateUp(cfg.Postgres.DSN); err != nil {
		fmt.Fprintln(a.Err, err)
		return ExitDependency
	}
	fmt.Fprintln(a.Out, "migrations applied")
	return ExitOK
}
func Main(args []string, out, err io.Writer) int { return App{Out: out, Err: err}.Run(args) }

var _ = strings.Builder{}
