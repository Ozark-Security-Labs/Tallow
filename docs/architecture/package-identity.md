# Package Identity

Package identity is ecosystem-aware. Do not use display names, URLs, maintainer names, or registry response casing as primary keys.

## Canonical package fields

A package record stores:
- `id`: internal ULID/UUID, not derived from untrusted text.
- `ecosystem`: controlled enum such as `npm`, `pypi`, `maven`, `go`, `crates`, `rubygems`.
- `canonical_name`: normalized identity used for uniqueness.
- `display_name`: latest registry spelling for UI only.
- `namespace`: ecosystem namespace/scope/owner where applicable; for npm scope excludes `@` in storage but display preserves it.
- `name`: unscoped normalized name.
- `registry_url`: normalized base registry URL.
- `created_at`, `updated_at`, `last_observed_at`.

Unique key: `ecosystem + registry_url + canonical_name`.

## Version fields

A version record stores:
- `id`.
- `package_id`.
- `version`: original version string from registry.
- `normalized_version`: ecosystem-normalized version for comparison and uniqueness.
- `published_at`: registry claimed publish time if available.
- `observed_at`: first Tallow observation time.
- `yanked` or `deprecated`: nullable ecosystem status.
- `metadata`: bounded JSONB for non-authoritative registry details.

Unique key: `package_id + normalized_version`.

## Ecosystem rules

npm:
- Package names are case-insensitive; canonicalize to lowercase.
- Preserve scope. `@Scope/Name` canonicalizes to `@scope/name`.
- The namespace is `scope`; name is unscoped package name.

PyPI:
- Use PEP 503 normalization: lowercase and collapse runs of `[-_.]+` to `-`.
- Display name is not a key.

Generic rule for future ecosystems:
- Implement a `CanonicalizePackageName(ecosystem, raw)` function before adding the adapter.
- Add table-driven tests for accepted, rejected, and equivalent names.

## Rejection rules

Reject package identities with:
- Empty ecosystem, registry URL, or name.
- Control characters.
- Names exceeding configured length.
- Path separators where ecosystem rules do not allow them.
- Names that normalize to empty.

## Safety notes

Package names are untrusted display text. Escape them in logs, SQL, HTML, shell commands, filesystem paths, and prompts. Storage paths must use encoded canonical components or internal IDs, not raw package names.
