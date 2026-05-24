package artifacts

import (
	"testing"
	"time"
)

func TestArtifactObservationPipelineEvents(t *testing.T) {
	obs := Observation{Ecosystem: "npm", Package: "pkg", Version: "1.0.0", ArtifactID: "artifact-1", ArtifactKind: "npm_tarball", StorageURI: "fs://artifacts/raw/npm/a/b/c", RegistryHashes: map[string]string{"sha512": "abc"}, LocalHashes: map[string]string{"sha256": "def"}, ObservedAt: time.Now().UTC()}
	dl, err := DownloadedEvent(obs)
	if err != nil || dl.Type != "artifact.downloaded" {
		t.Fatalf("downloaded %v %#v", err, dl)
	}
	hv, err := VerifiedEvent(obs)
	if err != nil || hv.Type != "artifact.hash.verified" {
		t.Fatalf("verified %v %#v", err, hv)
	}
}
