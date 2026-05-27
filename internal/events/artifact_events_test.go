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
	if SubjectAnalysisRequested != "tallow.analysis.requested.v1" {
		t.Fatal(SubjectAnalysisRequested)
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

func TestAnalysisRequestedEnvelope(t *testing.T) {
	payload := ArtifactEvent{Ecosystem: "npm", Package: "pkg", Version: "1.0.0", ArtifactID: "artifact-1", ArtifactKind: "npm_tarball", StorageURI: "snapshots/artifact-1", LocalHashes: map[string]string{"sha256": "def"}, ObservedAt: time.Now().UTC()}
	env, err := NewAnalysisRequestedEnvelope(payload)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != "analysis.requested" {
		t.Fatalf("unexpected type %q", env.Type)
	}
}

func TestArtifactEventsRejectMissingFields(t *testing.T) {
	if _, err := NewArtifactEnvelope("artifact.downloaded", ArtifactEvent{}); err == nil {
		t.Fatal("want validation error")
	}
	base := ArtifactEvent{Ecosystem: "npm", Package: "pkg", Version: "1", ArtifactID: "a", ArtifactKind: "npm_tarball", ObservedAt: time.Now().UTC()}
	if _, err := NewArtifactEnvelope("artifact.downloaded", base); err == nil {
		t.Fatal("want storage URI validation")
	}
}

func TestArtifactObservationEvents(t *testing.T) {
	TestArtifactEventsEnvelopeAndSubjects(t)
}
