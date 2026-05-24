# Finding Schema

Findings are deterministic analyzer outputs. They are evidence records, not prose reports.

## Required fields

- `schema_version`: e.g. `v1`.
- `id`: stable ID derived from rule, subject, and evidence coordinates.
- `rule_id`: stable namespaced identifier such as `builtin.npm.install-script-added`.
- `rule_version`.
- `analyzer_id` and `analyzer_version`.
- `subject`: package, version, artifact, snapshot, or diff pair.
- `title`: short deterministic title.
- `summary`: bounded deterministic explanation.
- `category`: `hash`, `metadata`, `script`, `credential`, `obfuscation`, `network`, `binary`, `maintainer`, `community`, `source_correlation`, etc.
- `severity_hint`: `info`, `low`, `medium`, `high`, `critical`.
- `confidence`: `low`, `medium`, `high`.
- `evidence`: non-empty list.
- `tags`: sorted list.
- `created_at`: analyzer run time; not part of stable ID.

## Evidence fields

Each evidence item stores:
- `kind`: `file`, `diff`, `hash`, `metadata`, `registry`, `community`, `source`.
- `artifact_id` or `snapshot_id` where applicable.
- `path` normalized to snapshot path.
- `start_line`, `end_line`, `start_byte`, `end_byte` where applicable.
- `snippet` optional bounded text, redacted.
- `value` for hashes/metadata claims.
- `description` deterministic human-readable explanation.

## Stable ID input

Stable finding IDs use:
`schema_version + rule_id + subject stable key + evidence kind/path/range/value hash`.

Do not include timestamps, analyzer runtime hostnames, random UUIDs, or unordered JSON.

## Severity ownership

Analyzer `severity_hint` is advisory. Go scoring and policy compute canonical severity using finding category, confidence, package criticality, source impact, and configured policy.

## Validation

Findings with missing evidence, unknown severity, unknown category, overlong snippets, or non-normalized paths must be rejected before persistence.
