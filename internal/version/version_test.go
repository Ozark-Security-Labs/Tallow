package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInfoDefaultsAndJSON(t *testing.T) {
	info := Info()
	if info.Version == "" || info.Commit == "" || info.Date == "" { t.Fatalf("empty version info: %#v", info) }
	b, err := json.Marshal(info); if err != nil { t.Fatal(err) }
	s := string(b)
	for _, f := range []string{"\"version\"", "\"commit\"", "\"date\""} { if !strings.Contains(s, f) { t.Fatalf("missing %s in %s", f, s) } }
}
