# Testing Strategy

Tallow tests must prove deterministic evidence handling, safe processing of hostile input, and idempotent distributed operation.

## Test layers

- Unit tests: pure identity, parsing, canonicalization, hash comparison, scheduling decisions, scoring, rule functions.
- Fixture tests: registry responses, archives, source manifests, analyzer inputs, event payloads.
- Integration tests: Postgres migrations/queries, NATS JetStream publish/consume, filesystem storage, adapter HTTP clients with recorded responses.
- End-to-end smoke tests: watch package -> observe version -> acquire artifact -> verify hash -> snapshot -> analyze -> finding -> alert.
- Security regression tests: traversal archives, malformed metadata, prompt-injection text, oversized files, duplicate events, same-version mutation.

## Required fixtures

Maintain fixtures under `testdata/` or language-specific fixture directories:

- npm package with normal tarball and integrity value.
- PyPI project with sdist and wheel for same version.
- Artifact whose registry hash claim is wrong.
- Same package/version where artifact bytes change between observations.
- Tar and zip archives with `../`, absolute paths, long paths, symlink escape, hardlink, device, FIFO, nested compression, and high file count.
- Package metadata containing prompt-injection strings.
- Dependency manifests and lockfiles for direct and transitive dependencies.

## Determinism expectations

- Sort map-derived output before persistence or JSON serialization.
- Use fixed clocks in tests; do not assert wall-clock timestamps except ranges.
- Stable IDs must be reproducible from documented natural keys.
- Analyzer findings must be sorted by severity rank, rule ID, evidence path, then stable finding ID.
- Snapshot manifests must sort paths bytewise after canonical path normalization.

## Idempotency expectations

Every consumer test must replay the same event at least twice. Expected result: one durable state transition, no duplicate findings, and an audit trail showing duplicate handling where useful.

Natural keys:
- Package: ecosystem + canonical name.
- Version: package ID + normalized version.
- Artifact: ecosystem + package + version + artifact type + filename/distribution tag + local sha256.
- Finding: rule ID + artifact ID or diff pair + normalized evidence coordinates + finding schema version.
- Alert: policy ID + finding ID + affected target ID.

## Go commands

- Run all Go tests: `go test ./...`
- Run race-sensitive scheduler tests: `go test -race ./internal/scheduler/...`
- Run integration tests: `go test -tags=integration ./...`

## Python commands

- Run analyzers: `uv run --project analyzers pytest`
- Lint analyzers: `uv run --project analyzers ruff check`
- Run analyzer tests with outbound network blocked: `TALLOW_ANALYZER_NETWORK_OFF=1 uv run --project analyzers pytest`
- Type-check when configured: `uv run --project analyzers mypy .`

## Web commands

- Run UI tests: `npm --prefix web test`
- Build UI: `npm --prefix web run build`

## What not to mock

Do not mock hash functions, path normalization, archive readers, event de-duplication, or database uniqueness behavior in tests whose purpose is security correctness. Use real implementations with small fixtures.

## Release gate

A release cannot be cut unless:
- All schemas validate examples.
- Migrations apply from empty database and from previous release.
- Safe-unpack malicious fixtures pass.
- Hash mismatch and same-version mutation fixtures produce findings.
- Prompt-injection fixtures cannot alter LLM system/developer instructions in tests.

## Foundation validation

Run `make test`, `make schema-validate`, `make generate-check`, and `docker compose config` before milestone review. Contract changes must update JSON Schemas and golden fixtures together.
