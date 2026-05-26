package analyzers

import (
	"encoding/json"
	"time"
)

const ContractVersion = "v1"

type AnalyzerInput struct {
	ContractVersion  string            `json:"contract_version"`
	JobID            string            `json:"job_id"`
	AnalysisType     string            `json:"analysis_type"`
	Subject          Subject           `json:"subject"`
	Artifacts        *ArtifactRefs     `json:"artifacts,omitempty"`
	SnapshotRefs     *SnapshotRefs     `json:"snapshot_refs,omitempty"`
	HashVerification *HashVerification `json:"hash_verification,omitempty"`
	Options          *Options          `json:"options,omitempty"`
}

type Subject struct {
	Ecosystem   string  `json:"ecosystem"`
	PackageName string  `json:"package_name"`
	Version     *string `json:"version,omitempty"`
	FromVersion *string `json:"from_version,omitempty"`
	ToVersion   *string `json:"to_version,omitempty"`
	PackageID   *string `json:"package_id,omitempty"`
	ArtifactID  *string `json:"artifact_id,omitempty"`
	SnapshotID  *string `json:"snapshot_id,omitempty"`
}

type ArtifactEntry struct {
	ArtifactID   string `json:"artifact_id"`
	SHA256       string `json:"sha256,omitempty"`
	Filename     string `json:"filename,omitempty"`
	SizeBytes    int64  `json:"size_bytes,omitempty"`
	SnapshotPath string `json:"snapshot_path,omitempty"`
}

type ArtifactRefs struct {
	From *ArtifactEntry `json:"from,omitempty"`
	To   *ArtifactEntry `json:"to,omitempty"`
}

type SnapshotEntry struct {
	SnapshotID   string `json:"snapshot_id"`
	Root         string `json:"root"`
	ManifestPath string `json:"manifest_path"`
}

type SnapshotRefs struct {
	From *SnapshotEntry `json:"from,omitempty"`
	To   *SnapshotEntry `json:"to,omitempty"`
}

type HashVerification struct {
	ArtifactID     string `json:"artifact_id"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ObservedSHA256 string `json:"observed_sha256"`
	Source         string `json:"source"`
}

type Options struct {
	EnabledRules         []string `json:"enabled_rules,omitempty"`
	DisabledRules        []string `json:"disabled_rules,omitempty"`
	MaxFileBytes         int64    `json:"max_file_bytes,omitempty"`
	MaxFindingsPerRule   int      `json:"max_findings_per_rule,omitempty"`
	AllowBinaryPackages  *bool    `json:"allow_binary_packages,omitempty"`
	AllowedBinaryPaths   []string `json:"allowed_binary_paths,omitempty"`
	HighEntropyMinLen    int      `json:"high_entropy_min_length,omitempty"`
	HighEntropyThreshold float64  `json:"high_entropy_threshold,omitempty"`
	FailFast             *bool    `json:"fail_fast,omitempty"`
}

type AnalyzerOutput struct {
	ContractVersion string          `json:"contract_version"`
	JobID           string          `json:"job_id"`
	Analyzer        AnalyzerInfo    `json:"analyzer"`
	Status          string          `json:"status"`
	Findings        []Finding       `json:"findings"`
	Errors          []AnalyzerError `json:"errors"`
	Metrics         AnalyzerMetrics `json:"metrics"`
}

type AnalyzerInfo struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	RulesetVersion string `json:"ruleset_version"`
}

type Finding struct {
	SchemaVersion   string            `json:"schema_version"`
	ID              string            `json:"id"`
	RuleID          string            `json:"rule_id"`
	RuleVersion     string            `json:"rule_version"`
	AnalyzerID      string            `json:"analyzer_id"`
	AnalyzerVersion string            `json:"analyzer_version"`
	Subject         FindingSubject    `json:"subject"`
	Title           string            `json:"title"`
	Summary         string            `json:"summary"`
	Category        string            `json:"category"`
	SeverityHint    string            `json:"severity_hint"`
	Confidence      string            `json:"confidence"`
	Evidence        []FindingEvidence `json:"evidence"`
	Tags            []string          `json:"tags"`
	CreatedAt       time.Time         `json:"created_at"`
}

type FindingSubject struct {
	Ecosystem      string  `json:"ecosystem"`
	PackageName    string  `json:"package_name"`
	Version        *string `json:"version,omitempty"`
	FromVersion    *string `json:"from_version,omitempty"`
	ToVersion      *string `json:"to_version,omitempty"`
	PackageID      *string `json:"package_id,omitempty"`
	ArtifactID     *string `json:"artifact_id,omitempty"`
	SnapshotID     *string `json:"snapshot_id,omitempty"`
	FromArtifactID *string `json:"from_artifact_id,omitempty"`
	ToArtifactID   *string `json:"to_artifact_id,omitempty"`
}

type FindingEvidence struct {
	Kind            string `json:"kind"`
	ArtifactID      string `json:"artifact_id,omitempty"`
	SnapshotID      string `json:"snapshot_id,omitempty"`
	Path            string `json:"path,omitempty"`
	StartLine       *int   `json:"start_line,omitempty"`
	EndLine         *int   `json:"end_line,omitempty"`
	StartByte       *int64 `json:"start_byte,omitempty"`
	EndByte         *int64 `json:"end_byte,omitempty"`
	Excerpt         string `json:"excerpt,omitempty"`
	ExcerptRedacted *bool  `json:"excerpt_redacted,omitempty"`
	Description     string `json:"description,omitempty"`
	Key             string `json:"key,omitempty"`
	Value           string `json:"value,omitempty"`
	Algorithm       string `json:"algorithm,omitempty"`
	Observed        string `json:"observed,omitempty"`
	Claimed         string `json:"claimed,omitempty"`
	Magic           string `json:"magic,omitempty"`
	SizeBytes       *int64 `json:"size_bytes,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	ValueHash       string `json:"value_hash,omitempty"`
	Extra           json.RawMessage
}

type AnalyzerError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	RuleID  string `json:"rule_id,omitempty"`
}

type AnalyzerMetrics struct {
	RulesEvaluated     int `json:"rules_evaluated"`
	FilesScanned       int `json:"files_scanned"`
	FindingsEmitted    int `json:"findings_emitted"`
	RulesFailed        int `json:"rules_failed"`
	FilesSkippedSize   int `json:"files_skipped_size"`
	FilesSkippedBinary int `json:"files_skipped_binary"`
}

type RunResult struct {
	ExitCode   int
	Stdout     []byte
	Stderr     []byte
	Duration   time.Duration
	TimedOut   bool
	StartedAt  time.Time
	FinishedAt time.Time
}
