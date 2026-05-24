package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestArtifactEventsEnvelopeAndSubjects(t *testing.T) {
	if SubjectArtifactDownloaded != "tallow.artifact.downloaded.v1" {
		t.Fatal(SubjectArtifactDownloaded)
	}
	payload := ArtifactEvent{Ecosystem: "npm", Package: "pkg", Version: "1.0.0", ArtifactID: "artifact-1", ArtifactKind: "npm_tarball", StorageURI: "fs://artifacts/raw/npm/x/y/z", RegistryHashes: map[string]string{"sha512": "abc"}, LocalHashes: map[string]string{"sha256": "def"}, ObservedAt: time.Now().UTC()}
	env, err := NewArtifactEnvelope("artifact.downloaded", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Validate(); err != nil {
		t.Fatal(err)
	}
	var got ArtifactEvent
	if err := json.Unmarshal(env.Data, &got); err != nil || got.ArtifactID != "artifact-1" {
		t.Fatalf("bad payload %#v %v", got, err)
	}
}

func TestArtifactEventsRejectMissingFields(t *testing.T) {
	if _, err := NewArtifactEnvelope("artifact.downloaded", ArtifactEvent{}); err == nil {
		t.Fatal("want validation error")
	}
}

func TestArtifactObservationEvents(t *testing.T) {
	TestArtifactEventsEnvelopeAndSubjects(t)
}
