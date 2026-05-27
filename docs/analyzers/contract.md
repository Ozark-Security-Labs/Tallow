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
- `artifacts`: `from` / `to` artifact metadata. Each referenced artifact must
  include `artifact_id`, `sha256`, `filename`, `size_bytes`, and
  `snapshot_path`.
- `options`: analyzer execution options. All option keys listed below are
  required so analyzers receive deterministic defaults.

Conditionally required top-level fields:

- `snapshot_refs`: required for `snapshot` and `snapshot_diff` jobs. Snapshot
  jobs require `to`; snapshot diff jobs require both `from` and `to`.
- `hash_verification`: hash mismatch context for `hash_verification` jobs.

Supported `options` fields include `enabled_rules`, `disabled_rules`,
`max_file_bytes`, `max_findings_per_rule`, `allow_binary_packages`,
`allowed_binary_paths`, `high_entropy_min_length`, `high_entropy_threshold`,
and `fail_fast`. `allow_binary_packages` contains package names or
`ecosystem/name` entries for packages expected to ship native binaries.
`allowed_binary_paths` contains exact snapshot-relative POSIX paths for native
binaries a package is expected to ship.

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
    "from": {
      "artifact_id": "art_from_01",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "filename": "example-package-1.0.0.tgz",
      "size_bytes": 4096,
      "snapshot_path": "snapshots/art_from_01"
    },
    "to": {
      "artifact_id": "art_to_01",
      "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "filename": "example-package-1.0.1.tgz",
      "size_bytes": 8192,
      "snapshot_path": "snapshots/art_to_01"
    }
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
    "disabled_rules": [],
    "max_file_bytes": 1048576,
    "max_findings_per_rule": 100,
    "allow_binary_packages": [],
    "allowed_binary_paths": [],
    "high_entropy_min_length": 512,
    "high_entropy_threshold": 7.2,
    "fail_fast": false
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
