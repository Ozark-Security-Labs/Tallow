# Artifact Identity

An artifact is a specific downloadable distribution object for a package version. Multiple artifacts may exist for the same package version.

## Artifact fields

Store:
- `id`: internal ULID/UUID.
- `package_id` and `version_id`.
- `ecosystem` denormalized for query convenience.
- `artifact_type`: `npm_tarball`, `pypi_sdist`, `pypi_wheel`, `source_archive`, or future enum.
- `filename`: registry filename after path stripping.
- `download_url`: canonical URL as observed.
- `media_type`: registry/content-type claim if present.
- `size_bytes_claimed`: registry claim if present.
- `size_bytes_observed`: local byte count after download.
- `sha256`: locally computed lowercase hex string; nullable only before acquisition completes.
- `sha512`, `blake3`: optional local hashes if computed.
- `registry_hash_algorithm` and `registry_hash_value`: registry claim.
- `storage_uri`: content-addressed storage location.
- `first_observed_at`, `last_observed_at`.
- `acquisition_status`: `pending`, `downloaded`, `verified`, `hash_mismatch`, `failed`, `quarantined`.

## Uniqueness

Before download, de-duplicate by `version_id + artifact_type + filename + download_url`.
After local hashing, immutable identity is `version_id + artifact_type + filename + sha256`.

If the same pre-download key later resolves to a different sha256, create a new artifact row and emit a same-version mutation signal.

## Storage path

Filesystem storage path:

`artifacts/sha256/aa/bb/<sha256>/<safe-filename>`

Rules:
- `aa` and `bb` are first four hex chars of sha256.
- `safe-filename` is sanitized for display only; sha256 owns identity.
- Never derive parent directories from raw package names.
- Write to a temporary quarantine path first, fsync, then atomic rename where possible.

## Artifact state transitions

Allowed transitions:
- `pending -> downloaded`
- `downloaded -> verified`
- `downloaded -> hash_mismatch`
- `pending|downloaded -> failed`
- `hash_mismatch|failed -> quarantined`

Do not transition `hash_mismatch` to `verified` for the same bytes. A later corrected registry claim creates a new verification record, not a rewrite of history.

## Implemented artifact identity

Foundation supports `npm_tarball`, `pypi_sdist`, and `pypi_wheel`; same-version mutations are represented by a changed immutable digest for the same pre-download key.

- #32 Artifact identity is implemented in internal/identity with pre-download and immutable keys.
