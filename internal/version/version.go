package version

var Version = "dev"
var Commit = "unknown"
var Date = "unknown"

type InfoRecord struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func Info() InfoRecord { return InfoRecord{Version: Version, Commit: Commit, Date: Date} }
