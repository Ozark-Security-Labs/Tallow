package cli

import (
	"bytes"
	"encoding/json"
	"testing"
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
