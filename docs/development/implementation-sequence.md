# Implementation Sequence

This sequence is the canonical order for coding agents implementing Tallow. Do not skip ahead to analyzers, UI, or LLM features before the deterministic evidence spine exists.

## Invariants

- Build deterministic evidence first; optional LLM narrative is last.
- Public contracts must be schema-backed before producers/consumers depend on them.
- Every event handler must be idempotent by natural key or explicit de-duplication key.
- Package contents, registry metadata, release notes, README files, and maintainer text are hostile input.
- Never execute package code during observation, unpacking, analysis, or tests.

## Phase 0: repository and contracts

1. Keep the monorepo layout from `AGENTS.md`.
2. Add CI jobs for Go, Python, web, schemas, and docs links.
3. Define JSON schema for the common event envelope before adding event subjects.
4. Define database migrations before writing API handlers that persist objects.
5. Add fixtures for npm and PyPI packages with normal releases, yanked/deprecated releases, mutable same-version artifacts, missing hashes, and malformed metadata.

Exit criteria:
- `go test ./...`, Python tests, and schema validation run in CI.
- A new contributor can start Postgres, NATS, and filesystem storage locally.

## Phase 1: package and artifact identity

1. Implement package canonicalization and identity keys.
2. Implement artifact identity keys and content-addressed storage paths.
3. Add uniqueness constraints for package, version, artifact, and observation records.
4. Add typed Go models and database access methods.

Exit criteria:
- Same package observed with different case/URL spelling maps to one canonical package where ecosystem rules require it.
- Distinct distributions for the same version are distinct artifacts.

## Phase 2: registry adapters and polling

1. Implement adapter interfaces without analyzer coupling.
2. Implement npm and PyPI adapters first.
3. Add polling scheduler with jitter, leases, and backoff.
4. Publish `package.version.observed` events only after persistence succeeds.

Exit criteria:
- Polling is safe to run with multiple scheduler instances.
- Repeated observations do not create duplicate versions/artifacts.

## Phase 3: acquisition and hash verification

1. Download artifacts to quarantine paths.
2. Compute local hashes while streaming; enforce byte limits.
3. Compare registry claims to local hashes.
4. Persist verification records even on mismatch or missing claim.
5. Move verified bytes into content-addressed filesystem storage.

Exit criteria:
- Hash mismatch is a first-class finding input and never silently retried away.
- Downloader never writes outside configured storage roots.

## Phase 4: safe unpack and snapshots

1. Implement bounded unpack for tar, zip, wheel, and npm tarballs.
2. Reject path traversal, symlinks escaping root, devices, FIFOs, and archive bombs.
3. Generate artifact snapshots without executing install hooks.
4. Persist snapshot manifests and selected small text evidence.

Exit criteria:
- Snapshot generation is deterministic for identical bytes.
- Unsafe entries are recorded as evidence and do not stop safe metadata extraction unless configured fatal.

## Phase 5: analyzer contract and deterministic rules

1. Finalize analyzer input/output schemas.
2. Implement Python worker that accepts snapshot references and emits findings.
3. Implement rule registry and built-in rules.
4. Store findings in Postgres with stable IDs.

Exit criteria:
- Analyzer output ordering is stable.
- Findings cite evidence paths, byte ranges or line ranges where applicable, and rule IDs.

## Phase 6: scoring, policy, impact, and alerts

1. Compute canonical severity in Go from deterministic signals.
2. Correlate packages to source repositories and dependency graph nodes.
3. Propagate direct and transitive impact.
4. Route alerts with evidence bundles and reviewer actions.

Exit criteria:
- No alert depends on LLM output for severity.
- Operators can trace alert -> finding -> artifact -> local hash -> registry observation.

## Phase 7: UI, operations, and LLM narrative

1. Build UI views over existing API contracts only.
2. Add operational metrics and audit logs.
3. Add optional LLM summaries that consume evidence bundles after prompt-injection defenses are implemented.

Exit criteria:
- Disabling LLM configuration does not reduce detection, scoring, or alerting capability.
