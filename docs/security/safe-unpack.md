# Safe Unpack

Artifact extraction must reject path traversal, absolute paths, symlink/hardlink escapes, device files, archive bombs, oversized files, and malformed metadata. No package code execution by default.

## Typed unpack errors

Unsafe archives are reported with `unpack_rejected` and bounded evidence; raw archive contents are not logged.
