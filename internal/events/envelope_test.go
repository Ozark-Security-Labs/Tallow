package events

import (
	"context"
	"encoding/json"
	"github.com/Ozark-Security-Labs/Tallow/internal/requestid"
	"testing"
	"time"
)

func TestEnvelopeVersion(t *testing.T) {
	if ValidateEnvelopeVersion("1.0") != nil {
		t.Fatal()
	}
	if ValidateEnvelopeVersion("2.0") == nil {
		t.Fatal("want err")
	}
}
func TestRequestIDPropagation(t *testing.T) {
	ctx := requestid.WithContext(context.Background(), "rid")
	e := WithRequestID(ctx, Envelope{})
	if e.Trace.RequestID != "rid" {
		t.Fatal(e.Trace.RequestID)
	}
}
func TestArtifactObserved(t *testing.T) {
	a := ArtifactObserved{Package: map[string]string{"ecosystem": "npm"}, Version: map[string]string{"raw_version": "1.0.0"}, Artifact: map[string]string{"kind": "npm_tgz"}, RegistryHashes: map[string]string{"sha256": "abc"}, Source: "registry", ObservedAt: time.Now()}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(a)
	if len(b) == 0 {
		t.Fatal()
	}
}
