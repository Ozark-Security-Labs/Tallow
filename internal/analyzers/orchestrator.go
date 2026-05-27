package analyzers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/events"
)

type RunRecorder interface {
	RecordRun(context.Context, AnalyzerRunRecord) error
	RecordFindings(context.Context, string, []Finding) error
}

type EventPublisher interface {
	Publish(context.Context, string, events.Envelope) error
}

type SnapshotRootResolver interface {
	ResolveSnapshotRoot(context.Context, events.ArtifactEvent) (SnapshotEntry, error)
}

type SnapshotRootResolverFunc func(context.Context, events.ArtifactEvent) (SnapshotEntry, error)

func (f SnapshotRootResolverFunc) ResolveSnapshotRoot(
	ctx context.Context,
	event events.ArtifactEvent,
) (SnapshotEntry, error) {
	return f(ctx, event)
}

type AnalyzerRunRecord struct {
	ID              string
	JobID           string
	AnalyzerID      string
	AnalyzerVersion string
	RulesetVersion  string
	Status          string
	StartedAt       time.Time
	FinishedAt      time.Time
	Duration        time.Duration
	InputJSON       []byte
	OutputJSON      []byte
	ErrorJSON       []byte
}

type Orchestrator struct {
	Executor         Executor
	Recorder         RunRecorder
	Publisher        EventPublisher
	SnapshotResolver SnapshotRootResolver
	SnapshotRootDir  string
	Now              func() time.Time
}

func (o Orchestrator) HandleEnvelope(ctx context.Context, envelope events.Envelope) error {
	if envelope.Type != "analysis.requested" {
		return nil
	}
	var event events.ArtifactEvent
	if err := json.Unmarshal(envelope.Data, &event); err != nil {
		return fmt.Errorf("prepare analyzer input: %w", err)
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("prepare analyzer input: %w", err)
	}
	input, err := o.inputFromArtifactEvent(ctx, event)
	if err != nil {
		return fmt.Errorf("prepare analyzer input: %w", err)
	}
	return o.Run(ctx, input)
}

func (o Orchestrator) Run(ctx context.Context, input AnalyzerInput) error {
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if err := ValidateInputJSON(inputJSON); err != nil {
		return err
	}
	if o.Executor == nil {
		return fmt.Errorf("analyzer executor required")
	}
	result, runErr := o.Executor.Run(ctx, inputJSON)
	record := AnalyzerRunRecord{
		ID:         runID(input.JobID),
		JobID:      input.JobID,
		Status:     "failed",
		StartedAt:  result.StartedAt,
		FinishedAt: result.FinishedAt,
		Duration:   result.Duration,
		InputJSON:  inputJSON,
	}
	if record.StartedAt.IsZero() {
		record.StartedAt = o.now()
	}
	if record.FinishedAt.IsZero() {
		record.FinishedAt = o.now()
	}
	eventCode := ""
	eventMessage := ""
	var findings []Finding
	if result.TimedOut {
		record.Status = "failed"
		eventCode = "timeout"
		eventMessage = "analyzer timed out"
		record.ErrorJSON = errorJSON("timeout", "analyzer timed out")
	} else if runErr != nil {
		eventCode = "executor_failed"
		eventMessage = runErr.Error()
		record.ErrorJSON = errorJSON("executor_failed", runErr.Error())
	} else {
		output, err := ValidateOutputJSON(result.Stdout)
		if err != nil {
			eventCode = "invalid_output"
			eventMessage = err.Error()
			record.ErrorJSON = errorJSON("invalid_output", err.Error())
		} else if output.JobID != input.JobID {
			eventCode = "job_mismatch"
			eventMessage = "analyzer output job_id does not match input job_id"
			record.ErrorJSON = errorJSON(eventCode, eventMessage)
		} else {
			record.AnalyzerID = output.Analyzer.ID
			record.AnalyzerVersion = output.Analyzer.Version
			record.RulesetVersion = output.Analyzer.RulesetVersion
			record.Status = output.Status
			record.OutputJSON = result.Stdout
			findings = output.Findings
			if output.Status == "failed" {
				eventCode, eventMessage = analyzerFailure(output.Errors)
				record.ErrorJSON = errorJSON(eventCode, eventMessage)
			}
		}
	}
	if err := o.record(ctx, record, findings); err != nil {
		return err
	}
	return o.publishAnalysisEvent(ctx, record, len(findings), eventCode, eventMessage)
}

func (o Orchestrator) record(ctx context.Context, record AnalyzerRunRecord, findings []Finding) error {
	if o.Recorder == nil {
		return nil
	}
	if err := o.Recorder.RecordRun(ctx, record); err != nil {
		return err
	}
	return o.Recorder.RecordFindings(ctx, record.ID, findings)
}

func (o Orchestrator) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o Orchestrator) inputFromArtifactEvent(
	ctx context.Context,
	event events.ArtifactEvent,
) (AnalyzerInput, error) {
	snapshot, err := o.resolveSnapshotRoot(ctx, event)
	if err != nil {
		return AnalyzerInput{}, err
	}
	return InputFromArtifactEvent(event, snapshot), nil
}

func InputFromArtifactEvent(event events.ArtifactEvent, snapshot SnapshotEntry) AnalyzerInput {
	jobID := "analysis:" + event.ArtifactID
	version := event.Version
	artifactID := event.ArtifactID
	snapshotID := snapshot.SnapshotID
	return AnalyzerInput{
		ContractVersion: ContractVersion,
		JobID:           jobID,
		AnalysisType:    "snapshot",
		Subject: Subject{
			Ecosystem:   event.Ecosystem,
			PackageName: event.Package,
			Version:     &version,
			ArtifactID:  &artifactID,
			SnapshotID:  &snapshotID,
		},
		Artifacts: &ArtifactRefs{To: &ArtifactEntry{
			ArtifactID:   event.ArtifactID,
			SHA256:       eventSHA256(event),
			Filename:     event.ArtifactKind,
			SizeBytes:    0,
			SnapshotPath: event.StorageURI,
		}},
		SnapshotRefs: &SnapshotRefs{To: &SnapshotEntry{
			SnapshotID:   snapshot.SnapshotID,
			Root:         snapshot.Root,
			ManifestPath: snapshot.ManifestPath,
		}},
		Options: DefaultOptions(),
	}
}

func DefaultOptions() *Options {
	return &Options{
		EnabledRules:         []string{},
		DisabledRules:        []string{},
		MaxFileBytes:         1_048_576,
		MaxFindingsPerRule:   100,
		AllowBinaryPackages:  []string{},
		AllowedBinaryPaths:   []string{},
		HighEntropyMinLen:    512,
		HighEntropyThreshold: 7.2,
		FailFast:             boolPtr(false),
	}
}

func eventSHA256(event events.ArtifactEvent) string {
	for _, hashes := range []map[string]string{event.LocalHashes, event.RegistryHashes} {
		if hashes != nil && hashes["sha256"] != "" {
			return hashes["sha256"]
		}
	}
	return ""
}

func boolPtr(value bool) *bool { return &value }

func (o Orchestrator) resolveSnapshotRoot(
	ctx context.Context,
	event events.ArtifactEvent,
) (SnapshotEntry, error) {
	if o.SnapshotResolver != nil {
		return o.SnapshotResolver.ResolveSnapshotRoot(ctx, event)
	}
	return LocalSnapshotEntry(event.ArtifactID, event.StorageURI, o.SnapshotRootDir)
}

func LocalSnapshotEntry(artifactID, rawRoot, allowedRoot string) (SnapshotEntry, error) {
	if artifactID == "" || rawRoot == "" {
		return SnapshotEntry{}, fmt.Errorf("artifact event missing snapshot root")
	}
	if strings.Contains(rawRoot, "://") {
		return SnapshotEntry{}, fmt.Errorf("snapshot root must be a local filesystem path")
	}
	if strings.TrimSpace(allowedRoot) == "" {
		return SnapshotEntry{}, fmt.Errorf("snapshot root base required")
	}
	base, err := filepath.Abs(allowedRoot)
	if err != nil {
		return SnapshotEntry{}, err
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return SnapshotEntry{}, fmt.Errorf("resolve snapshot root base: %w", err)
	}
	candidate := rawRoot
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(base, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return SnapshotEntry{}, err
	}
	candidate, err = filepath.EvalSymlinks(candidate)
	if err != nil {
		return SnapshotEntry{}, fmt.Errorf("resolve snapshot root: %w", err)
	}
	rel, err := filepath.Rel(base, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return SnapshotEntry{}, fmt.Errorf("snapshot root escapes configured base")
	}
	return SnapshotEntry{
		SnapshotID:   artifactID,
		Root:         candidate,
		ManifestPath: filepath.Join(candidate, "manifest.json"),
	}, nil
}

func (o Orchestrator) publishAnalysisEvent(
	ctx context.Context,
	record AnalyzerRunRecord,
	findingsEmitted int,
	errorCode string,
	errorMessage string,
) error {
	if o.Publisher == nil {
		return nil
	}
	eventType := "analysis.completed"
	subject := events.SubjectAnalysisCompleted
	if record.Status != "ok" {
		eventType = "analysis.failed"
		subject = events.SubjectAnalysisFailed
		if errorCode == "" {
			errorCode = "analyzer_failed"
		}
		if errorMessage == "" {
			errorMessage = "analyzer reported failed status"
		}
	}
	envelope, err := events.NewAnalysisEnvelope(eventType, events.AnalysisEvent{
		JobID:           record.JobID,
		RunID:           record.ID,
		Status:          record.Status,
		AnalyzerID:      record.AnalyzerID,
		AnalyzerVersion: record.AnalyzerVersion,
		RulesetVersion:  record.RulesetVersion,
		FindingsEmitted: findingsEmitted,
		ErrorCode:       errorCode,
		ErrorMessage:    errorMessage,
		CompletedAt:     record.FinishedAt,
	})
	if err != nil {
		return err
	}
	return o.Publisher.Publish(ctx, subject, envelope)
}

func analyzerFailure(errors []AnalyzerError) (string, string) {
	if len(errors) == 0 {
		return "analyzer_failed", "analyzer reported failed status"
	}
	return errors[0].Code, errors[0].Message
}

func runID(jobID string) string {
	digest := sha256.Sum256([]byte(jobID))
	return "run_" + hex.EncodeToString(digest[:])[:32]
}

func errorJSON(code, message string) []byte {
	payload, _ := json.Marshal([]AnalyzerError{{Code: code, Message: message}})
	return payload
}
