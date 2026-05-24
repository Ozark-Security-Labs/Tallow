# Artifact Snapshots

A snapshot is deterministic metadata extracted from an artifact without executing package code.

## Snapshot fields

- `id`.
- `artifact_id`.
- `snapshot_version`: schema version.
- `created_at`.
- `manifest_uri`: storage URI for full JSON manifest.
- `file_count`.
- `total_uncompressed_bytes`.
- `truncated`: boolean.
- `unsafe_entry_count`.
- `content_sample_policy`: e.g. `small_text_only`.

## File manifest entry fields

Each entry records:
- `path`: normalized relative path using `/`.
- `type`: `file`, `directory`, `symlink`, `hardlink`, `other`, `rejected`.
- `size_bytes`.
- `mode`.
- `sha256` for regular files within size policy.
- `text_encoding` if detected.
- `line_count` for text files when cheap.
- `evidence_uri` for stored small text excerpts or full small files.
- `unsafe_reason` for rejected entries.

## Normalization

- Reject absolute paths and paths escaping root after cleaning.
- Normalize separators to `/`.
- Remove `.` path segments.
- Preserve case; do not case-fold paths.
- Sort entries by normalized path, then type.

## Limits

Configurable defaults:
- Max archive bytes: 256 MiB.
- Max uncompressed bytes: 1 GiB.
- Max file count: 100,000.
- Max single file text evidence: 1 MiB.
- Max nested archive depth: 1 unless explicitly enabled.

## Diff snapshots

Diff by normalized path and file sha256:
- `added`: path exists only in new snapshot.
- `removed`: path exists only in old snapshot.
- `modified`: path exists in both and sha256 differs.
- `type_changed`: path exists in both but type differs.

Do not diff generated timestamps or archive ordering. Findings should cite snapshot IDs and paths, not temporary extraction paths.

## Implementation notes

The snapshot writer converts deterministic unpack manifests and artifact metadata
into byte-stable JSON documents containing artifact identity, manifest URI,
metadata, file inventory digest, sorted files, and evidence references. The diff
writer compares snapshots by normalized path/type/size/hash only and emits stable
added, removed, modified, and metadata-delta sections without semantic guessing
or raw blob embedding.
