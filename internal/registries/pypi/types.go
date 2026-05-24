package pypi

import "time"

type Metadata struct {
	Info     Info              `json:"info"`
	Releases map[string][]File `json:"releases"`
	URLs     []File            `json:"urls"`
}

type Info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type File struct {
	Filename       string            `json:"filename"`
	PackageType    string            `json:"packagetype"`
	URL            string            `json:"url"`
	Digests        map[string]string `json:"digests"`
	Yanked         bool              `json:"yanked"`
	YankedReason   string            `json:"yanked_reason"`
	UploadTimeISO  string            `json:"upload_time_iso_8601"`
	Size           int64             `json:"size"`
	PythonVersion  string            `json:"python_version"`
	RequiresPython string            `json:"requires_python"`
}

type Artifact struct {
	Project        string
	Version        string
	Filename       string
	Kind           string
	URL            string
	Yanked         bool
	YankedReason   string
	UploadedAt     time.Time
	RegistryHashes map[string]string
	LocalHashes    map[string]string
	Verification   Verification
}

type Verification struct {
	Status string
	Source string
	Trust  string
}
