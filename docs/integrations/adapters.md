# Adapter Interfaces

Adapters isolate external systems from Tallow core. They must normalize data, preserve raw claims as evidence, and avoid side effects beyond reads.

## Registry adapter interface

A registry adapter provides:
- `Ecosystem() string`.
- `CanonicalizePackageName(raw string) (CanonicalPackage, error)`.
- `FetchPackage(ctx, canonicalName, cursor) (PackageObservation, error)`.
- `FetchArtifact(ctx, artifactRef, destination) (DownloadResult, error)`.

`PackageObservation` includes package identity, versions, artifact refs, registry hash claims, publish times, deprecation/yank status, cursors, ETag/Last-Modified, and bounded raw metadata URI.

## SCM adapter interface

An SCM adapter provides a provider-neutral interface with:

- repository resolution from normalized owner/name/URL claims;
- manifest fetch by path and revision/commit without cloning;
- revision metadata for branch, tag, or commit references; and
- cursor polling for repository inventories.

The Go contract is represented by `internal/scm.Adapter` with `ResolveRepository`, `FetchManifest`, `RevisionMetadata`, and `PollRepositories`. GitHub implements the contract in this milestone. GitLab, Codeberg, Forgejo, and Gitea should map the same methods to their APIs in future work; this milestone documents those extension points only and does not implement those providers.

SCM adapters must not clone entire repositories unless configured. Prefer API file fetches and size limits.

## Notification adapter interface

A notification adapter sends alert payloads and returns delivery status. It must support idempotency keys so retries do not spam recipients.

## Error model

Adapters return typed errors:
- `NotFound`.
- `RateLimited` with retry time when available.
- `Unauthorized`.
- `Forbidden`.
- `Temporary`.
- `InvalidResponse`.
- `Unsupported`.

Do not parse strings in scheduler logic; use typed errors.

## Safety rules

- Never pass untrusted package names to shell commands.
- Enforce HTTP timeouts, response byte limits, and redirect limits.
- Do not follow redirects to private IP ranges unless explicitly allowed for self-hosted registries.
- Preserve raw registry claims separately from normalized fields.
- Redact tokens in logs and error messages.

## Adapter tests

Every adapter requires:
- Canonicalization table tests.
- Recorded response fixture tests.
- Rate limit/backoff behavior tests.
- Malformed response tests.
- Idempotent observation upsert tests.
