package analyzers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/events"
)

type fakeExecutor struct {
	result RunResult
	err    error
	input  []byte
}

func (f *fakeExecutor) Run(_ context.Context, input []byte) (RunResult, error) {
	f.input = append([]byte(nil), input...)
	return f.result, f.err
}

type fakeRecorder struct {
	runs        []AnalyzerRunRecord
	findings    []Finding
	runErr      error
	findingsErr error
}

func (f *fakeRecorder) RecordRun(_ context.Context, run AnalyzerRunRecord) error {
	if f.runErr != nil {
		return f.runErr
	}
	f.runs = append(f.runs, run)
	return nil
}

func (f *fakeRecorder) RecordFindings(_ context.Context, _ string, findings []Finding) error {
	if f.findingsErr != nil {
		return f.findingsErr
	}
	f.findings = append(f.findings, findings...)
	return nil
}

type publishedEvent struct {
	subject  string
	envelope events.Envelope
}

type fakePublisher struct {
	events []publishedEvent
	err    error
}

func (f *fakePublisher) Publish(_ context.Context, subject string, envelope events.Envelope) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, publishedEvent{subject: subject, envelope: envelope})
	return nil
}

func baseInput() AnalyzerInput {
	version := "1.0.0"
	artifactID := "art_1"
	snapshotID := "snap_1"
	return AnalyzerInput{
		ContractVersion: ContractVersion,
		JobID:           "job_1",
		AnalysisType:    "snapshot",
		Subject: Subject{
			Ecosystem:   "npm",
			PackageName: "pkg",
			Version:     &version,
			ArtifactID:  &artifactID,
		},
		Artifacts: &ArtifactRefs{To: &ArtifactEntry{
			ArtifactID:   artifactID,
			SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Filename:     "pkg.tgz",
			SizeBytes:    1,
			SnapshotPath: "snapshots/art_1",
		}},
		SnapshotRefs: &SnapshotRefs{To: &SnapshotEntry{
			SnapshotID:   snapshotID,
			Root:         "/tmp/tallow-test-snapshot",
			ManifestPath: "/tmp/tallow-test-snapshot/manifest.json",
		}},
		Options: DefaultOptions(),
	}
}

func outputJSON(jobID string, findings []Finding) []byte {
	if findings == nil {
		findings = []Finding{}
	}
	payload := AnalyzerOutput{
		ContractVersion: ContractVersion,
		JobID:           jobID,
		Analyzer: AnalyzerInfo{
			ID:             "builtin.rules",
			Version:        "0.1.0",
			RulesetVersion: "2026.05.26",
		},
		Status:   "ok",
		Findings: findings,
		Errors:   []AnalyzerError{},
		Metrics:  AnalyzerMetrics{},
	}
	data, _ := json.Marshal(payload)
	return data
}

func sampleAnalyzerFinding() Finding {
	version := "1.0.0"
	artifactID := "art_1"
	return Finding{
		SchemaVersion:   "v1",
		ID:              "fin_v1_00000000000000000000000000000001",
		RuleID:          "npm.lifecycle.install_script",
		RuleVersion:     "1.0.0",
		AnalyzerID:      "builtin.rules",
		AnalyzerVersion: "0.1.0",
		Subject: FindingSubject{
			Ecosystem:   "npm",
			PackageName: "pkg",
			Version:     &version,
			ArtifactID:  &artifactID,
		},
		Title:        "title",
		Summary:      "summary",
		Category:     "script",
		SeverityHint: "medium",
		Confidence:   "high",
		Evidence: []FindingEvidence{{
			Kind:       "file",
			ArtifactID: "art_1",
			Path:       "package.json",
		}},
		Tags:      []string{"npm"},
		CreatedAt: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	}
}

func TestOrchestratorRecordsSuccessAndFindings(t *testing.T) {
	input := baseInput()
	executor := &fakeExecutor{result: RunResult{
		Stdout:     outputJSON(input.JobID, []Finding{sampleAnalyzerFinding()}),
		StartedAt:  time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 5, 26, 12, 0, 1, 0, time.UTC),
		Duration:   time.Second,
	}}
	recorder := &fakeRecorder{}
	publisher := &fakePublisher{}
	err := (Orchestrator{Executor: executor, Recorder: recorder, Publisher: publisher}).Run(
		context.Background(), input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.runs) != 1 || recorder.runs[0].Status != "ok" {
		t.Fatalf("runs: %#v", recorder.runs)
	}
	if recorder.runs[0].AnalyzerID != "builtin.rules" || len(recorder.findings) != 1 {
		t.Fatalf("run/findings not recorded: %#v %#v", recorder.runs, recorder.findings)
	}
	if len(publisher.events) != 1 || publisher.events[0].subject != events.SubjectAnalysisCompleted {
		t.Fatalf("completion event not published: %#v", publisher.events)
	}
}

func TestOrchestratorInvalidOutputDoesNotCrashLoop(t *testing.T) {
	executor := &fakeExecutor{result: RunResult{Stdout: []byte(`{"bad":true}`)}}
	recorder := &fakeRecorder{}
	err := (Orchestrator{Executor: executor, Recorder: recorder}).Run(context.Background(), baseInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.runs) != 1 || recorder.runs[0].Status != "failed" {
		t.Fatalf("runs: %#v", recorder.runs)
	}
	if len(recorder.runs[0].ErrorJSON) == 0 {
		t.Fatal("expected validation error json")
	}
	if len(recorder.runs[0].OutputJSON) != 0 {
		t.Fatal("invalid analyzer output must not be persisted as output_json")
	}
}

func TestOrchestratorExecutorFailureAndTimeoutDoNotCrashLoop(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result RunResult
		err    error
	}{
		{name: "failure", err: errors.New("boom")},
		{name: "timeout", result: RunResult{TimedOut: true, Stdout: outputJSON("job_1", nil)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &fakeRecorder{}
			err := (Orchestrator{
				Executor: &fakeExecutor{result: tc.result, err: tc.err},
				Recorder: recorder,
			}).Run(context.Background(), baseInput())
			if err != nil {
				t.Fatal(err)
			}
			if len(recorder.runs) != 1 || recorder.runs[0].Status != "failed" {
				t.Fatalf("runs: %#v", recorder.runs)
			}
		})
	}
}

func TestOrchestratorPropagatesRecorderErrors(t *testing.T) {
	recorder := &fakeRecorder{findingsErr: errors.New("write failed")}
	executor := &fakeExecutor{result: RunResult{Stdout: outputJSON("job_1", []Finding{sampleAnalyzerFinding()})}}
	err := (Orchestrator{Executor: executor, Recorder: recorder}).Run(context.Background(), baseInput())
	if err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected recorder error, got %v", err)
	}
}

func TestOrchestratorRejectsMismatchedOutputJobID(t *testing.T) {
	recorder := &fakeRecorder{}
	publisher := &fakePublisher{}
	executor := &fakeExecutor{result: RunResult{Stdout: outputJSON("other_job", nil)}}
	err := (Orchestrator{Executor: executor, Recorder: recorder, Publisher: publisher}).Run(
		context.Background(), baseInput(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.runs) != 1 || recorder.runs[0].Status != "failed" {
		t.Fatalf("runs: %#v", recorder.runs)
	}
	if len(recorder.runs[0].OutputJSON) != 0 {
		t.Fatal("mismatched analyzer output must not be persisted as output_json")
	}
	if len(publisher.events) != 1 || publisher.events[0].subject != events.SubjectAnalysisFailed {
		t.Fatalf("failure event not published: %#v", publisher.events)
	}
}

func TestHandleEnvelopeConsumesArtifactEvent(t *testing.T) {
	snapshotBase := t.TempDir()
	snapshotRoot := filepath.Join(snapshotBase, "snapshots", "art_1")
	if err := os.MkdirAll(snapshotRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	event := events.ArtifactEvent{
		Ecosystem:    "npm",
		Package:      "pkg",
		Version:      "1.0.0",
		ArtifactID:   "art_1",
		ArtifactKind: "tarball",
		StorageURI:   "snapshots/art_1",
		LocalHashes:  map[string]string{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ObservedAt:   time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	}
	data, _ := json.Marshal(event)
	executor := &fakeExecutor{result: RunResult{Stdout: outputJSON("analysis:art_1", nil)}}
	recorder := &fakeRecorder{}
	err := (Orchestrator{Executor: executor, Recorder: recorder, SnapshotRootDir: snapshotBase}).HandleEnvelope(
		context.Background(),
		events.Envelope{
			ID:         "evt_1",
			Type:       "artifact.downloaded",
			Version:    "1.0",
			OccurredAt: time.Now(),
			Producer:   "test",
			Trace:      events.Trace{TraceID: "trace_1"},
			Data:       data,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var input AnalyzerInput
	if err := json.Unmarshal(executor.input, &input); err != nil {
		t.Fatal(err)
	}
	if input.JobID != "analysis:art_1" || input.Subject.PackageName != "pkg" {
		t.Fatalf("unexpected input: %#v", input)
	}
	if input.SnapshotRefs == nil || input.SnapshotRefs.To == nil || input.SnapshotRefs.To.Root == "" {
		t.Fatalf("snapshot refs missing: %#v", input)
	}
	if input.SnapshotRefs.To.Root != snapshotRoot {
		t.Fatalf("unexpected snapshot root: %#v", input.SnapshotRefs.To)
	}
	if len(recorder.runs) != 1 {
		t.Fatalf("runs: %#v", recorder.runs)
	}
}

func TestHandleEnvelopeRejectsStorageURIAsSnapshotRoot(t *testing.T) {
	event := events.ArtifactEvent{
		Ecosystem:    "npm",
		Package:      "pkg",
		Version:      "1.0.0",
		ArtifactID:   "art_1",
		ArtifactKind: "tarball",
		StorageURI:   "fs://artifacts/raw/pkg",
		LocalHashes:  map[string]string{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ObservedAt:   time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	}
	data, _ := json.Marshal(event)
	err := (Orchestrator{Executor: &fakeExecutor{}, SnapshotRootDir: t.TempDir()}).HandleEnvelope(
		context.Background(), events.Envelope{Type: "artifact.downloaded", Data: data},
	)
	if err == nil {
		t.Fatal("expected non-local snapshot root error")
	}
}

func TestLocalSnapshotEntryRejectsRootEscape(t *testing.T) {
	if _, err := LocalSnapshotEntry("art_1", "../outside", t.TempDir()); err == nil {
		t.Fatal("expected root escape error")
	}
}

func TestLocalSnapshotEntryRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on windows")
	}
	base := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(base, "snapshots", "art_1")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalSnapshotEntry("art_1", "snapshots/art_1", base); err == nil {
		t.Fatal("expected symlink escape error")
	}
}

func TestValidateOutputRejectsFindingWithoutEvidence(t *testing.T) {
	finding := sampleAnalyzerFinding()
	finding.Evidence = nil
	if _, err := ValidateOutputJSON(outputJSON("job_1", []Finding{finding})); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateOutputRejectsSchemaViolations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(Finding) Finding
	}{
		{
			name: "unsafe path",
			mutate: func(f Finding) Finding {
				f.Evidence[0].Path = "../secret"
				return f
			},
		},
		{
			name: "invalid severity",
			mutate: func(f Finding) Finding {
				f.SeverityHint = "urgent"
				return f
			},
		},
		{
			name: "overlong excerpt",
			mutate: func(f Finding) Finding {
				redacted := true
				f.Evidence[0].Excerpt = string(make([]byte, 241))
				f.Evidence[0].ExcerptRedacted = &redacted
				return f
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			finding := tc.mutate(sampleAnalyzerFinding())
			if _, err := ValidateOutputJSON(outputJSON("job_1", []Finding{finding})); err == nil {
				t.Fatal("expected schema validation error")
			}
		})
	}
}

func TestValidateOutputRejectsAdditionalProperties(t *testing.T) {
	payload := map[string]any{}
	if err := json.Unmarshal(outputJSON("job_1", nil), &payload); err != nil {
		t.Fatal(err)
	}
	payload["unexpected"] = true
	data, _ := json.Marshal(payload)
	if _, err := ValidateOutputJSON(data); err == nil {
		t.Fatal("expected schema validation error")
	}
}

func TestValidateOutputRejectsAdditionalEvidenceProperties(t *testing.T) {
	payload := map[string]any{}
	if err := json.Unmarshal(outputJSON("job_1", []Finding{sampleAnalyzerFinding()}), &payload); err != nil {
		t.Fatal(err)
	}
	findings := payload["findings"].([]any)
	evidence := findings[0].(map[string]any)["evidence"].([]any)
	evidence[0].(map[string]any)["unexpected"] = true
	data, _ := json.Marshal(payload)
	if _, err := ValidateOutputJSON(data); err == nil {
		t.Fatal("expected schema validation error")
	}
}

func TestHandleEnvelopeRejectsMalformedArtifactObserved(t *testing.T) {
	data := []byte(`{
		"package": "not-object",
		"version": {"raw_version": "1.0.0"},
		"artifact": {"id": "art_1", "kind": "tarball"},
		"registry_hashes": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"source": "registry",
		"observed_at": "2026-05-26T12:00:00Z",
		"storage_ref": "/tmp/snapshot"
	}`)
	err := (Orchestrator{Executor: &fakeExecutor{}}).HandleEnvelope(
		context.Background(),
		events.Envelope{Type: "artifact.observed", Data: data},
	)
	if err == nil {
		t.Fatal("expected malformed observed event error")
	}
}
