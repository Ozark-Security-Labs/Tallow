# Analyzer Contract

Analyzer contracts are versioned JSON documents shared between Go orchestration and Python analyzers.

## Input shape

```json
{
  "contract_version": "v1",
  "job_id": "job_01...",
  "analysis_type": "version_diff",
  "package": {"ecosystem":"npm","name":"example","from_version":"1.0.0","to_version":"1.0.1"},
  "artifacts": {"from":{"artifact_id":"art_1"},"to":{"artifact_id":"art_2"}},
  "snapshot_refs": {"from":"...","to":"..."},
  "options": {"enable_ast":true,"max_file_bytes":1048576}
}
```

## Output shape

```json
{
  "contract_version": "v1",
  "job_id": "job_01...",
  "analyzer": {"id":"builtin.rules","version":"0.1.0"},
  "status": "ok",
  "findings": []
}
```

Schemas in `schemas/` are authoritative.
