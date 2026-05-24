# Safe Unpack

Artifact extraction must reject path traversal, absolute paths, symlink/hardlink escapes, device files, archive bombs, oversized files, and malformed metadata. No package code execution by default.

## Typed unpack errors

Unsafe archives are reported with `unpack_rejected` and bounded evidence; raw archive contents are not logged.

## Archive risks

Safe unpack must reject traversal, symlink/hardlink escapes, devices, FIFOs, archive bombs, excessive file counts, long paths, nested compression surprises, and unsafe metadata. Rejections use `unpack_rejected` with bounded evidence.
