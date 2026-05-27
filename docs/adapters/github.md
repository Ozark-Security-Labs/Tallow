# GitHub Adapter

The GitHub adapter resolves repository evidence from npm/PyPI package metadata and bounded GitHub REST API calls. It never clones repositories and unit tests use `httptest` fixtures.

Supported repository URL forms include `https://github.com/owner/repo`, `git+https://github.com/owner/repo.git`, and `git@github.com:owner/repo.git`. Metadata claims are recorded with their source field, original URL, normalized owner/name, and evidence key.

Tokens are optional for public metadata. When configured, tokens are sent only as Authorization headers and must be redacted from logs/errors. Missing, private, not found, unauthorized, forbidden, and rate-limited repositories return typed adapter errors instead of panics.

The adapter captures repository URL, default branch, visibility, tags, and bounded manifest content by path/revision. Release enrichment can be added through the same interface without changing correlation evidence semantics.
