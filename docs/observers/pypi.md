# PyPI artifact observer

The PyPI observer reads the JSON API for a configured project, selects files for
a requested version, and represents `sdist` and `bdist_wheel` files as distinct
artifact kinds. The observer validates `digests.sha256` before analyzer dispatch
and records BLAKE2b-256 values when the JSON API advertises them.

Yanked status, yanked reason, upload time, filename, URL, and registry digest
claims are preserved as observation metadata. Missing registry digests record
`unverified_missing_registry_hash` and are blocked from analyzer dispatch by the
artifact verification policy unless explicitly allowed.
