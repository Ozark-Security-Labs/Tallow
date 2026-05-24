# Tallow Architecture Overview

Tallow is a self-hosted dependency release surveillance system. It is built around a deterministic evidence pipeline: observe registry state, validate artifacts, snapshot and diff package contents, run static analyzers, store findings, calculate impact, and notify operators.

## Core components

- **Go control plane**: API, CLI, scheduler, registry adapters, SCM adapters, artifact download, hash verification, scoring, policy, notifications, auth, and LLM orchestration.
- **Python analyzer workers**: AST inspection, deterministic rules, entropy/string scanning, Semgrep/YARA adapters, and ecosystem-specific static analysis.
- **NATS JetStream**: durable event bus for package observations, analyzer jobs, impact calculations, alerts, and notifications.
- **PostgreSQL**: canonical state for packages, versions, artifacts, observations, dependency graphs, findings, alerts, users, and audit events.
- **Object storage**: filesystem by default; S3-compatible storage later.
- **React UI**: triage console for packages, findings, dependency paths, alerts, and settings.

## Data flow

1. Dependency inventory is imported from source providers, lockfiles, manifests, SBOMs, or watchlists.
2. Registry observers poll watched packages and discover versions/artifacts.
3. Artifact acquisition downloads artifacts and validates registry-provided hashes against locally computed hashes.
4. Safe unpack/snapshot logic extracts bounded file manifests and content metadata.
5. Python analyzers run deterministic rules over snapshots/diffs and emit structured findings.
6. Go scorer/policy calculates canonical severity and confidence.
7. Dependency graph propagation identifies directly and transitively affected packages and repositories.
8. Alert routing notifies via email/Teams first, with future channels behind the same route abstraction.
9. Optional LLM narrative enrichment summarizes deterministic evidence but never owns severity.

## Non-negotiables

- Registry hashes are claims, not truth; Tallow verifies locally.
- Same-version artifact mutation is critical until explained.
- Package contents are hostile input.
- Analyzer output must be deterministic and evidence-bound.
- LLMs are optional narrative assistants, not authorities.
