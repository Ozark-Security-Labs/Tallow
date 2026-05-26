# Analyzer Engine

The analyzer engine is split deliberately: Go orchestrates, Python inspects.

## Responsibilities

Go:
- consumes observation events
- prepares analyzer jobs
- enforces timeouts and resource limits
- validates analyzer output against schemas
- persists runs/findings
- applies canonical scoring/policy

Python:
- reads normalized artifacts/snapshots/diffs
- performs deterministic AST/string/entropy/rule checks
- emits structured findings with evidence

## Analyzer contract

Analyzer input and output are versioned JSON documents. Schemas live in `schemas/`.

Findings must include:
- stable rule ID
- severity suggestion
- confidence
- evidence path/spans
- concise rationale
- analyzer ID/version

Canonical alert severity is assigned by Go policy, not by LLMs.

## Go orchestration flow

The control-plane orchestrator consumes artifact observation/download envelopes,
builds a `v1` analyzer input document, executes the configured analyzer command
with bounded timeout, validates output before persistence, and records every run
as `ok` or `failed` with timing and error JSON. Executor failures, invalid JSON,
schema/contract failures, and timeouts are recorded as failed analyzer runs and do
not crash the worker loop.

Findings emitted by successful analyzers are upserted by stable finding ID.
Operator triage status is preserved on replay; analyzer reruns update evidence and
metadata without reopening dismissed or triaged findings.
