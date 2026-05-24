package npm

import "time"

type Metadata struct {
	Name     string             `json:"name"`
	Versions map[string]Version `json:"versions"`
	Time     map[string]string  `json:"time"`
}

type Version struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    Dist   `json:"dist"`
}

type Dist struct {
	Tarball   string `json:"tarball"`
	Integrity string `json:"integrity"`
	Shasum    string `json:"shasum"`
}

type Artifact struct {
	Package        string
	Version        string
	Filename       string
	TarballURL     string
	Integrity      string
	Shasum         string
	PublishedAt    time.Time
	RegistryHashes map[string]string
	LocalHashes    map[string]string
	Verification   Verification
}

type Verification struct {
	Status string
	Source string
	Trust  string
}
