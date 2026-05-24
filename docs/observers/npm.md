# npm artifact observer

The npm observer reads package metadata from a configured registry URL, selects a
specific version, downloads the referenced tarball, and verifies registry hash
claims before any unpacking or analyzer dispatch.

Verification preference:

1. `dist.integrity` SRI (`sha512` preferred, then `sha256`, then `sha1`).
2. `dist.shasum` SHA-1 fallback with a lower-trust marker.
3. Missing registry hash records `unverified_missing_registry_hash` and is
   blocked from analyzer dispatch by the artifact verification policy unless an
   operator explicitly permits it.

The observer computes local SHA-1, SHA-256, and SHA-512 over the downloaded bytes
using streaming readers. Mismatches are structured evidence and fail closed.
