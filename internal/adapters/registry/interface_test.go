package registry_test

import (
	"context"
	"encoding/json"
	reg "github.com/Ozark-Security-Labs/Tallow/internal/adapters/registry"
	"github.com/Ozark-Security-Labs/Tallow/internal/adapters/registry/fake"
	npmadapter "github.com/Ozark-Security-Labs/Tallow/internal/adapters/registry/npm"
	pypiadapter "github.com/Ozark-Security-Labs/Tallow/internal/adapters/registry/pypi"
	"os"
	"testing"
)

func TestRegistryAdapterContracts(t *testing.T) {
	adapters := []reg.Adapter{fake.Adapter{}, npmadapter.Adapter{}, pypiadapter.Adapter{}}
	for _, a := range adapters {
		if a.Ecosystem() == "" {
			t.Fatal("missing ecosystem")
		}
		if _, err := a.CanonicalPackageName("Pkg_Name"); err != nil {
			t.Fatalf("%s: %v", a.Ecosystem(), err)
		}
	}
	arts, err := (fake.Adapter{}).ListArtifacts(context.Background(), "pkg", "1.0.0")
	if err != nil || len(arts) != 1 || len(arts[0].RegistryHashes) == 0 {
		t.Fatalf("arts=%+v err=%v", arts, err)
	}
}

func TestRegistryFixtureRoundTrip(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/adapter-fixtures/registry/package-version.npm.json")
	if err != nil {
		t.Fatal(err)
	}
	var v reg.VersionMetadata
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Identity.Ecosystem != reg.EcosystemNPM {
		t.Fatalf("fixture=%+v", v)
	}
}
