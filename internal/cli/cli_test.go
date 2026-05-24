package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/config"
)

func run(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	code := Main(args, &o, &e)
	return code, o.String(), e.String()
}
func TestHelpVersionAndPlaceholders(t *testing.T) {
	if c, o, _ := run("--help"); c != 0 || o == "" {
		t.Fatal(c, o)
	}
	c, o, _ := run("version", "--json")
	if c != 0 {
		t.Fatal(c)
	}
	var m map[string]string
	if json.Unmarshal([]byte(o), &m) != nil || m["version"] == "" {
		t.Fatal(o)
	}
	if c, _, _ := run("observe"); c != ExitNotImplemented {
		t.Fatal(c)
	}
	if c, _, _ := run("bad"); c != ExitUsage {
		t.Fatal(c)
	}
}
func TestDBUsage(t *testing.T) {
	if c, _, _ := run("db"); c != ExitUsage {
		t.Fatal(c)
	}
}

func TestServerRunsWithParsedConfig(t *testing.T) {
	var o, e bytes.Buffer
	cfgPath := t.TempDir() + "/tallow.yml"
	if err := os.WriteFile(cfgPath, []byte("server:\n  listen_address: \":9090\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got string
	app := App{Out: &o, Err: &e, RunServer: func(cfg config.Config) error {
		got = cfg.Server.ListenAddress
		return nil
	}}
	if code := app.Run([]string{"server", "--config", cfgPath}); code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, e.String())
	}
	if got != ":9090" {
		t.Fatalf("server runner got %q", got)
	}
}
