# Storage Layout

Tallow stores artifacts and generated evidence under deterministic, sanitized paths. Storage paths must never be created by concatenating untrusted package names, filenames, registry URLs, or archive paths.

## Storage roots

- `raw/`: downloaded package artifacts after registry hash validation or explicit unverified quarantine.
- `quarantine/`: artifacts that failed registry hash validation or safe-unpack policy and are retained for evidence according to retention settings.
- `manifests/`: safe-unpack file inventories.
- `snapshots/`: normalized artifact snapshot documents.
- `diffs/`: deterministic artifact/version diff documents.
- `analysis/`: analyzer input/output payloads and redacted evidence summaries.
- `reports/`: exported alert, SARIF, Markdown, JSON, and evidence bundle reports.

## URI rules

A storage URI should be derived from canonical identity and content hashes:

```text
raw/{ecosystem}/{package_digest}/{version_digest}/{artifact_sha256}
```

Human-readable labels may be stored in PostgreSQL metadata, but filesystem/object paths should use sanitized identifiers and hashes.

## Retention modes

- `metadata_only`: store hashes, metadata, findings, and selected reports; do not retain raw artifacts after analysis unless required for a critical alert.
- `suspicious_only`: default. Retain artifacts and extracted evidence for suspicious or failed observations.
- `full_archive`: retain all observed artifacts and derived outputs.

## Required tests

- Path traversal inputs cannot escape the storage root.
- Unicode/control characters are rejected or normalized according to documented rules.
- Same input identity creates the same URI.
- Distinct wheel/sdist/npm artifact variants do not collide.
