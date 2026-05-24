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
