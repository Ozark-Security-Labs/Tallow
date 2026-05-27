# Dependency Graph and Impact Propagation

Tallow models dependency inventory as a graph rather than a flat package list. Graph data is evidence-bound: every edge records where the relationship came from, how exact it is, and whether it describes a direct dependency declaration or a transitive path observed in a lockfile/SBOM.

## Lockfile-preferred philosophy

Confidence order is:

1. Lockfile or resolved dependency graph (`resolved_lockfile`).
2. SBOM or package-manager native graph command in controlled mode (`resolved_lockfile` when versions and paths are concrete).
3. Registry metadata dependency declarations (`declared_metadata`).
4. Manifest constraints only (`declared_metadata`) or deterministic name-only heuristics (`inferred`).

Loose manifests and registry metadata may create package-level edges with constraints, but they must not claim exact resolved impact unless a lockfile/SBOM/resolver supplies the version and path. When sources conflict, Tallow keeps the lower-confidence edge and evidence instead of upgrading certainty.

## Dependency nodes and edges

Package version nodes reuse canonical `packages` and `package_versions` records. Dependency edges store:

- `parent_package_version_id`: package version that declares or contains the dependency.
- `child_package_id`: dependency package identity.
- `child_package_version_id`: resolved child version when known.
- `constraint_text`: declared range or requirement string.
- `resolved_version`: resolved child version string when known.
- `scope`: `runtime`, `dev`, `optional`, `peer`, `build`, `test`, or `unknown`.
- `relationship`: `direct` or `transitive`.
- `is_optional`, `is_dev`, `is_build`: explicit boolean flags for common reviewer filters.
- `confidence`: `resolved_lockfile`, `declared_metadata`, or `inferred`.
- `source_type`: `lockfile`, `manifest`, `sbom`, `registry_metadata`, or `manual`.
- `manifest_path`, `lockfile_path`, `dependency_path`, and `evidence_refs`.
- `edge_fingerprint`: deterministic uniqueness key excluding database IDs and timestamps.

Edges are sorted deterministically by depth, ecosystem/name/version, source/manifest path, and path fingerprint before presentation.

## Status language

Intrinsic package-version status values are:

- `clean`: no known relevant finding.
- `suspicious`: deterministic evidence exists but compromise is not confirmed.
- `compromised_intrinsic`: the package artifact itself contains high-confidence malicious or dangerous evidence.
- `unknown`: insufficient evidence.
- `suppressed`: operator-reviewed suppression.

`affected_by_transitive` is a derived impact status, not an intrinsic package status. Direct dependencies that resolve to compromised transitives are marked **affected by transitive compromise**, not intrinsically malicious unless their own artifact has evidence.

## Impact paths

Impact records must preserve paths:

```text
repo -> manifest -> direct-package@version -> ... -> compromised-package@version
```

Each path references the source finding/status and includes depth, path fingerprint, and evidence references so operators can explain exactly why a repo or package version is affected.


## Traversal bounds

Dependent traversal walks reverse dependency edges from a suspicious or compromised package version to direct and transitive dependents. Implementations must:

- reject traversal without explicit `max_depth` and `max_paths_per_root` bounds;
- suppress cycles by tracking package versions already present in the current path;
- preserve diamond paths as distinct evidence until the per-root path limit is reached; and
- return paths in deterministic depth/name/fingerprint order.
