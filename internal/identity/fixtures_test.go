package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixture struct {
	CaseID             string    `json:"case_id"`
	Ecosystem          Ecosystem `json:"ecosystem"`
	RawName            string    `json:"raw_name"`
	WantNormalizedName string    `json:"want_normalized_name"`
	WantNamespace      string    `json:"want_namespace"`
	WantName           string    `json:"want_name"`
	WantErrorCode      string    `json:"want_error_code"`
}

func TestFixtures(t *testing.T) {
	for _, p := range []string{"../../testdata/identity/npm/cases.json", "../../testdata/identity/pypi/cases.json"} {
		b, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatal(err)
		}
		var fs []fixture
		if err := json.Unmarshal(b, &fs); err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			got, err := NormalizePackageName(f.Ecosystem, f.RawName)
			if f.WantErrorCode != "" {
				if err == nil {
					t.Fatalf("%s want err", f.CaseID)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", f.CaseID, err)
			}
			if got.NormalizedName != f.WantNormalizedName {
				t.Fatalf("%s got %#v", f.CaseID, got)
			}
		}
	}
}
