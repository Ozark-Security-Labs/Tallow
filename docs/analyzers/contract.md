# Analyzer Contract

Analyzer contracts are versioned JSON documents shared between Go orchestration and Python analyzers. Schemas in `schemas/` are authoritative.

## Contract version

Current contract version: `v1`.

## Input shape

Required top-level fields:

- `contract_version`: must be `v1`.
- `job_id`: non-empty stable job identifier.
- `analysis_type`: one of `snapshot`, `snapshot_diff`, or `hash_verification`.
- `subject`: package and artifact coordinates.

Optional top-level fields:

- `artifacts`: `from` / `to` artifact metadata (`artifact_id`, `sha256`, `filename`, `size_bytes`, `snapshot_path`).
- `snapshot_refs`: `from` / `to` snapshot roots (`snapshot_id`, `root`, `manifest_path`).
- `hash_verification`: hash mismatch context for `hash_verification` jobs.
- `options`: analyzer execution options.

Example:

```json
{
  "contract_version": "v1",
  "job_id": "job_01...",
  "analysis_type": "snapshot_diff",
  "subject": {
    "ecosystem": "npm",
    "package_name": "example-package",
    "from_version": "1.0.0",
    "to_version": "1.0.1"
  },
  "artifacts": {
    "from": {"artifact_id": "art_from_01"},
    "to": {"artifact_id": "art_to_01"}
  },
  "snapshot_refs": {
    "from": {
      "snapshot_id": "snap_from_01",
      "root": "/data/snapshots/snap_from_01",
      "manifest_path": "/data/snapshots/snap_from_01/manifest.json"
    },
    "to": {
      "snapshot_id": "snap_to_01",
      "root": "/data/snapshots/snap_to_01",
      "manifest_path": "/data/snapshots/snap_to_01/manifest.json"
    }
  },
  "options": {
    "enabled_rules": ["npm.lifecycle.install_script"],
    "max_file_bytes": 1048576
  }
}
```

See `schemas/examples/analyzer-input.snapshot-diff.npm.json` for a full example.

## Output shape

Required top-level fields:

- `contract_version`: must be `v1`.
- `job_id`: echoes input job ID.
- `analyzer`: `id`, `version`, and `ruleset_version`.
- `status`: `ok` or `failed`.
- `findings`: array of finding objects (see [finding-schema.md](finding-schema.md)).
- `errors`: deterministic error records (may be empty).
- `metrics`: deterministic counters only.

Example:

```json
{
  "contract_version": "v1",
  "job_id": "job_01...",
  "analyzer": {
    "id": "builtin.rules",
    "version": "0.1.0",
    "ruleset_version": "2026.05.26"
  },
  "status": "ok",
  "findings": [],
  "errors": [],
  "metrics": {
    "rules_evaluated": 0,
    "files_scanned": 0,
    "findings_emitted": 0,
    "rules_failed": 0,
    "files_skipped_size": 0,
    "files_skipped_binary": 0
  }
}
```

See `schemas/examples/analyzer-output.findings.npm.json` for a full example.

## Compatibility rules

- Additive optional fields are minor-compatible within `v1`.
- Removing required fields, renaming fields, or changing stable ID inputs requires a new contract version.
- Rule detection logic changes require a `rule_version` bump even when the contract version stays `v1`.
- Go orchestration rejects analyzer output that fails JSON Schema validation before persistence.

## Validation

Run schema validation from the repository root:

```bash
python scripts/validate_schemas.py
```

Or via Makefile:

```bash
make schema-validate
```
