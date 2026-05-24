# Hash Verification

Registry hashes are claims. Tallow always computes local hashes from downloaded bytes and stores the comparison result.

## Verification record fields

Store one record per artifact acquisition attempt:
- `id`.
- `artifact_id`.
- `attempt` integer.
- `source`: registry metadata field name such as `dist.integrity`, `digests.sha256`, URL fragment, or lockfile.
- `claimed_algorithm`.
- `claimed_value_normalized`.
- `local_sha256`.
- `local_sha512` if computed.
- `bytes_read`.
- `status`: `match`, `mismatch`, `missing_claim`, `unsupported_algorithm`, `download_failed`.
- `error_code` and `error_message` bounded and sanitized.
- `verified_at`.

## Algorithm policy

- Always compute sha256 locally.
- Compute sha512 when registry provides sha512 or npm SRI.
- Accept SRI strings only after parsing algorithm/value pairs.
- Prefer strongest supported claimed algorithm when multiple claims exist, but store all claims if practical.
- Unsupported algorithms do not pass verification.

## Mismatch behavior

On mismatch:
1. Persist local hashes and claimed hashes.
2. Mark artifact acquisition `hash_mismatch`.
3. Store bytes in quarantine or content-addressed storage according to retention config.
4. Emit a deterministic finding candidate.
5. Do not unpack by default unless `allow_analyze_hash_mismatch=true` for research environments.

## Missing claim behavior

Missing registry hash is not automatically malicious. Store `missing_claim`, compute local sha256, and allow unpack unless policy requires registry hash.

## Streaming requirements

- Enforce max artifact bytes while streaming.
- Hash bytes exactly as received after HTTP decoding policy is applied; disable transparent decompression for artifact downloads unless the registry contract requires it.
- Use temporary files; do not keep whole artifacts in memory.
- Verify TLS using system trust by default; custom CA is config, not code.

## Test expectations

- Correct npm SRI match.
- Correct PyPI sha256 match.
- Wrong claim produces `mismatch` and finding input.
- Missing claim produces `missing_claim` without false critical severity.
- HTTP gzip/content-encoding cannot cause hashing of a different byte stream than stored.


## Failure policy

Default verification policy is fail-closed:

- `verified`: artifact may be unpacked and may dispatch analyzer jobs.
- `unverified_missing_registry_hash`: artifact may proceed only when an operator explicitly enables unverified unpack or analysis; analyzer dispatch defaults to false.
- `mismatch`: artifact is quarantined, emits a critical integrity event/finding candidate, and never dispatches analyzers by default.
