# Finding Schema

Findings are deterministic analyzer outputs. They are evidence records, not prose reports. The authoritative JSON Schema is `schemas/finding.schema.json`.

## Required fields

- `schema_version`: must be `v1`.
- `id`: stable ID derived from rule, subject, and evidence coordinates (`fin_v1_<32 lowercase hex chars>`).
- `rule_id`: stable namespaced identifier such as `npm.lifecycle.install_script`.
- `rule_version`: semver or date-based rule version string.
- `analyzer_id` and `analyzer_version`.
- `subject`: package, version, artifact, snapshot, or diff pair coordinates.
- `title`: short deterministic title (max 200 chars).
- `summary`: bounded deterministic explanation (max 2000 chars).
- `category`: one of `hash`, `metadata`, `script`, `credential`, `obfuscation`, `network`, `binary`, `maintainer`, `community`, `source_correlation`.
- `severity_hint`: `info`, `low`, `medium`, `high`, or `critical`.
- `confidence`: `low`, `medium`, or `high`.
- `evidence`: non-empty list of evidence references.
- `tags`: sorted list of short labels.
- `created_at`: analyzer run timestamp (RFC3339); not part of stable ID.

## Subject fields

Finding subjects mirror analyzer input subjects and may include diff coordinates:

- `ecosystem`: `npm` or `pypi`.
- `package_name`.
- `version`, `from_version`, `to_version` (nullable where not applicable).
- `package_id`, `artifact_id`, `snapshot_id` (nullable).
- `from_artifact_id`, `to_artifact_id` for diff findings (nullable).

## Evidence fields

Each evidence item conforms to `schemas/evidence/evidence-ref.v1.schema.json` with a constrained `kind`:

- `file`: normalized snapshot-relative path with optional line/byte ranges.
- `diff`: diff-relative evidence for added/changed content.
- `hash`: hash comparison claims without storing raw blob bytes.
- `metadata`: registry or package metadata claims.
- `registry`: registry-specific metadata.
- `community`: community signal references.
- `source`: correlated source repository evidence.

Common evidence properties:

- `artifact_id` (required by evidence schema).
- `snapshot_id` where applicable.
- `path` normalized to snapshot-relative POSIX path.
- `start_line`, `end_line`, `start_byte`, `end_byte` where applicable.
- `excerpt` optional bounded text (max 240 chars), redacted when sensitive.
- `excerpt_redacted` boolean flag.
- `hash` for hash/metadata digests.
- `description` deterministic human-readable explanation.

Python SDK helpers accept a `snippet` parameter alias and emit schema-compatible `excerpt` fields.

## Stable ID input

Stable finding IDs use canonical JSON over:

- `schema_version`
- `rule_id`
- normalized subject stable keys (`ecosystem`, `package_name`, version coordinates, artifact/snapshot IDs)
- normalized evidence keys (`kind`, `artifact_id`, `snapshot_id`, `path`, ranges, `value_hash`)

Evidence is sorted by `kind`, `path`, numeric ranges, and `value_hash` before hashing.

Do not include timestamps, analyzer runtime hostnames, random UUIDs, or unordered JSON in ID inputs.

## Severity ownership

Analyzer `severity_hint` is advisory. Go scoring and policy compute canonical severity using finding category, confidence, package criticality, source impact, and configured policy.

## Validation

Findings with missing evidence, unknown severity, unknown category, overlong excerpts, or non-normalized paths must be rejected before persistence.

- Absolute paths, traversal segments, and unredacted excerpt ambiguity are rejected.
- See `schemas/evidence/evidence-ref.v1.schema.json` for path constraints.

## Compatibility rules

- Additive optional finding fields are minor-compatible within `v1`.
- Changing stable ID inputs or required fields requires a new `schema_version`.
- Rule logic changes require a `rule_version` bump.
