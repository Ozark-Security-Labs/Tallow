package analyzers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/events"
)

type RunRecorder interface {
	RecordRun(context.Context, AnalyzerRunRecord) error
	RecordFindings(context.Context, string, []Finding) error
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
	Executor Executor
	Recorder RunRecorder
	Now      func() time.Time
}

func (o Orchestrator) HandleEnvelope(ctx context.Context, envelope events.Envelope) error {
	if envelope.Type != "artifact.observed" && envelope.Type != "artifact.downloaded" {
		return nil
	}
	var event events.ArtifactEvent
	if err := json.Unmarshal(envelope.Data, &event); err != nil || event.ArtifactID == "" {
		input, inputErr := inputFromArtifactObserved(envelope.Data)
		if inputErr != nil {
			return fmt.Errorf("prepare analyzer input: %w", inputErr)
		}
		return o.Run(ctx, input)
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("prepare analyzer input: %w", err)
	}
	if event.StorageURI == "" {
		return fmt.Errorf("prepare analyzer input: artifact event missing snapshot root")
	}
	input := InputFromArtifactEvent(event)
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
	if result.TimedOut {
		record.Status = "failed"
		record.ErrorJSON = errorJSON("timeout", "analyzer timed out")
		o.record(ctx, record, nil)
		return nil
	}
	if runErr != nil {
		record.ErrorJSON = errorJSON("executor_failed", runErr.Error())
		o.record(ctx, record, nil)
		return nil
	}
	output, err := ValidateOutputJSON(result.Stdout)
	if err != nil {
		record.ErrorJSON = errorJSON("invalid_output", err.Error())
		record.OutputJSON = result.Stdout
		o.record(ctx, record, nil)
		return nil
	}
	record.AnalyzerID = output.Analyzer.ID
	record.AnalyzerVersion = output.Analyzer.Version
	record.RulesetVersion = output.Analyzer.RulesetVersion
	record.Status = output.Status
	record.OutputJSON = result.Stdout
	o.record(ctx, record, output.Findings)
	return nil
}

func (o Orchestrator) record(ctx context.Context, record AnalyzerRunRecord, findings []Finding) {
	if o.Recorder == nil {
		return
	}
	if err := o.Recorder.RecordRun(ctx, record); err != nil {
		return
	}
	_ = o.Recorder.RecordFindings(ctx, record.ID, findings)
}

func (o Orchestrator) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func InputFromArtifactEvent(event events.ArtifactEvent) AnalyzerInput {
	jobID := "analysis:" + event.ArtifactID
	version := event.Version
	artifactID := event.ArtifactID
	snapshotID := event.ArtifactID
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
			Filename:     event.ArtifactKind,
			SnapshotPath: event.StorageURI,
		}},
		SnapshotRefs: &SnapshotRefs{To: &SnapshotEntry{
			SnapshotID:   snapshotID,
			Root:         event.StorageURI,
			ManifestPath: "manifest.json",
		}},
	}
}

func inputFromArtifactObserved(data []byte) (AnalyzerInput, error) {
	var observed events.ArtifactObserved
	if err := json.Unmarshal(data, &observed); err != nil {
		return AnalyzerInput{}, err
	}
	if err := observed.Validate(); err != nil {
		return AnalyzerInput{}, err
	}
	packageObj, ok := observed.Package.(map[string]any)
	if !ok {
		return AnalyzerInput{}, fmt.Errorf("artifact observed event package must be object")
	}
	versionObj, ok := observed.Version.(map[string]any)
	if !ok {
		return AnalyzerInput{}, fmt.Errorf("artifact observed event version must be object")
	}
	artifactObj, ok := observed.Artifact.(map[string]any)
	if !ok {
		return AnalyzerInput{}, fmt.Errorf("artifact observed event artifact must be object")
	}
	packageName, _ := packageObj["name"].(string)
	if packageName == "" {
		packageName, _ = packageObj["raw_name"].(string)
	}
	ecosystem, _ := packageObj["ecosystem"].(string)
	version, _ := versionObj["raw_version"].(string)
	artifactID, _ := artifactObj["id"].(string)
	kind, _ := artifactObj["kind"].(string)
	if artifactID == "" {
		artifactID, _ = artifactObj["artifact_id"].(string)
	}
	if ecosystem == "" || packageName == "" || version == "" || artifactID == "" || observed.StorageRef == "" {
		return AnalyzerInput{}, fmt.Errorf("artifact observed event missing analyzer fields")
	}
	artifactIDCopy := artifactID
	versionCopy := version
	snapshotID := artifactID
	return AnalyzerInput{
		ContractVersion: ContractVersion,
		JobID:           "analysis:" + artifactID,
		AnalysisType:    "snapshot",
		Subject: Subject{
			Ecosystem:   ecosystem,
			PackageName: packageName,
			Version:     &versionCopy,
			ArtifactID:  &artifactIDCopy,
			SnapshotID:  &snapshotID,
		},
		Artifacts: &ArtifactRefs{To: &ArtifactEntry{
			ArtifactID:   artifactID,
			Filename:     kind,
			SnapshotPath: observed.StorageRef,
		}},
		SnapshotRefs: &SnapshotRefs{To: &SnapshotEntry{
			SnapshotID:   snapshotID,
			Root:         observed.StorageRef,
			ManifestPath: "manifest.json",
		}},
	}, nil
}

func runID(jobID string) string {
	digest := sha256.Sum256([]byte(jobID))
	return "run_" + hex.EncodeToString(digest[:])[:32]
}

func errorJSON(code, message string) []byte {
	payload, _ := json.Marshal([]AnalyzerError{{Code: code, Message: message}})
	return payload
}
