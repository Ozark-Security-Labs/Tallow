package analyzers

import (
	"context"
	"encoding/json"
	"errors"
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
	runs     []AnalyzerRunRecord
	findings []Finding
}

func (f *fakeRecorder) RecordRun(_ context.Context, run AnalyzerRunRecord) error {
	f.runs = append(f.runs, run)
	return nil
}

func (f *fakeRecorder) RecordFindings(_ context.Context, _ string, findings []Finding) error {
	f.findings = append(f.findings, findings...)
	return nil
}

func baseInput() AnalyzerInput {
	version := "1.0.0"
	artifactID := "art_1"
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
	}
}

func outputJSON(jobID string, findings []Finding) []byte {
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
	err := (Orchestrator{Executor: executor, Recorder: recorder}).Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.runs) != 1 || recorder.runs[0].Status != "ok" {
		t.Fatalf("runs: %#v", recorder.runs)
	}
	if recorder.runs[0].AnalyzerID != "builtin.rules" || len(recorder.findings) != 1 {
		t.Fatalf("run/findings not recorded: %#v %#v", recorder.runs, recorder.findings)
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

func TestHandleEnvelopeConsumesArtifactEvent(t *testing.T) {
	event := events.ArtifactEvent{
		Ecosystem:    "npm",
		Package:      "pkg",
		Version:      "1.0.0",
		ArtifactID:   "art_1",
		ArtifactKind: "tarball",
		StorageURI:   "fs://snapshots/art_1",
		ObservedAt:   time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	}
	data, _ := json.Marshal(event)
	executor := &fakeExecutor{result: RunResult{Stdout: outputJSON("analysis:art_1", nil)}}
	recorder := &fakeRecorder{}
	err := (Orchestrator{Executor: executor, Recorder: recorder}).HandleEnvelope(
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
	if len(recorder.runs) != 1 {
		t.Fatalf("runs: %#v", recorder.runs)
	}
}

func TestValidateOutputRejectsFindingWithoutEvidence(t *testing.T) {
	finding := sampleAnalyzerFinding()
	finding.Evidence = nil
	if _, err := ValidateOutputJSON(outputJSON("job_1", []Finding{finding})); err == nil {
		t.Fatal("expected validation error")
	}
}
