# Safe Unpack

Artifact extraction must reject path traversal, absolute paths, symlink/hardlink escapes, device files, archive bombs, oversized files, and malformed metadata. No package code execution by default.

## Typed unpack errors

Unsafe archives are reported with `unpack_rejected` and bounded evidence; raw archive contents are not logged.

## Archive risks

Safe unpack must reject traversal, symlink/hardlink escapes, devices, FIFOs, archive bombs, excessive file counts, long paths, nested compression surprises, and unsafe metadata. Rejections use `unpack_rejected` with bounded evidence.

## Implementation notes

The Go safe-unpack package reads tar, tgz, zip, and wheel archives as hostile
input and emits deterministic manifests instead of extracting package contents to
host paths. It rejects traversal, absolute paths, unsafe symlink and hardlink
targets, device files, malformed entries, and configured file-count/file-size/
total-size limit violations. Rejected entries are recorded with bounded rejection
codes for reviewer evidence.

Synthetic fixtures under `testdata/archives/` exercise tar traversal, symlink
escape, hardlink escape, zip-slip, wheel zip-slip, and oversize-marker cases.
