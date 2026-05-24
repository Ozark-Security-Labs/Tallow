# Source Correlation

Source correlation links observed dependency packages to repositories, manifests, lockfiles, services, and owners.

## Source records

Repository/source fields:
- `id`.
- `provider`: `github`, `gitlab`, `bitbucket`, `local`, `sbom`, `manual`.
- `external_id`.
- `url`.
- `default_branch`.
- `owner`, `repo` where applicable.
- `visibility`.
- `last_indexed_at`.

Manifest fields:
- `id`, `source_id`.
- `path`.
- `ecosystem`.
- `manifest_type`: `package_json`, `package_lock`, `requirements_txt`, `poetry_lock`, `sbom`, etc.
- `commit_sha` or import version.
- `parsed_at`.

Dependency edge fields:
- `source_id`, `manifest_id`.
- `package_id`.
- `required_spec`.
- `resolved_version_id` where known.
- `relationship`: `direct`, `transitive`, `dev`, `optional`, `peer`, `build`.
- `path`: dependency chain for transitive edges when available.

## Correlation rules

- Lockfiles and SBOMs provide resolved versions and should outrank loose manifests.
- Loose manifests create package-level impact with uncertain version unless range resolution is implemented.
- Manual watchlists are package surveillance inputs, not source impact by themselves.
- Correlation must be recomputed when package canonicalization rules change.

## Impact propagation

For each finding:
1. Identify affected package and version range.
2. Match exact resolved versions first.
3. Match package-level unknown versions as `possibly_affected`.
4. Traverse dependency graph to affected sources.
5. Create alert candidates per policy.

## Evidence

Alerts must include:
- Source repository and manifest path.
- Direct or transitive relationship.
- Dependency path for transitive matches.
- Package version observed.
- Finding IDs and artifact IDs.

## Privacy

Do not send private repository contents to LLM or external services by default. Store only manifest paths and dependency metadata required for correlation unless users enable deeper source analysis.
