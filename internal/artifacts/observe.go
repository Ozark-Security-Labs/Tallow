package artifacts

import (
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/events"
)

type Observation struct {
	Ecosystem      string
	Package        string
	Version        string
	ArtifactID     string
	ArtifactKind   string
	StorageURI     string
	RegistryHashes map[string]string
	LocalHashes    map[string]string
	ObservedAt     time.Time
}

func DownloadedEvent(o Observation) (events.Envelope, error) {
	return events.NewArtifactEnvelope("artifact.downloaded", events.ArtifactEvent{Ecosystem: o.Ecosystem, Package: o.Package, Version: o.Version, ArtifactID: o.ArtifactID, ArtifactKind: o.ArtifactKind, StorageURI: o.StorageURI, RegistryHashes: o.RegistryHashes, LocalHashes: o.LocalHashes, ObservedAt: o.ObservedAt})
}

func VerifiedEvent(o Observation) (events.Envelope, error) {
	return events.NewArtifactEnvelope("artifact.hash.verified", events.ArtifactEvent{Ecosystem: o.Ecosystem, Package: o.Package, Version: o.Version, ArtifactID: o.ArtifactID, ArtifactKind: o.ArtifactKind, StorageURI: o.StorageURI, RegistryHashes: o.RegistryHashes, LocalHashes: o.LocalHashes, ObservedAt: o.ObservedAt})
}
