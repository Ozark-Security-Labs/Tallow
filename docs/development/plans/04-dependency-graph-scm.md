# Dependency Graph + SCM Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build Tallow's dependency graph and SCM milestone: persist direct and transitive dependency graphs, ingest lockfile-preferred dependency evidence, traverse dependents safely, store `affected_by_transitive` status without overstating intrinsic compromise, resolve GitHub source metadata, correlate package/artifact/source evidence, and define the SCM adapter interface for future providers.

**Architecture:** Go remains the control plane. PostgreSQL stores canonical package/version nodes, dependency edges, traversal results, package statuses, source repositories, SCM revision metadata, manifests, and correlation evidence. Graph ingestion is idempotent and evidence-bound, with lockfiles/SBOMs outranking declared metadata; traversal is deterministic, cycle-safe, depth-limited, path-limited, and used by propagation to create derived impact records rather than mutating intrinsic package status.

**Tech Stack:** Go 1.23+, PostgreSQL, sqlc, golang-migrate, pgx, chi/OpenAPI, JSON Schema, GitHub REST API via `net/http`, deterministic fixture tests, `httptest`, GitHub Actions.

**Issues covered:** #19, #20, #21, #22, #65, #66, #67, #68, #69.

---

## Non-negotiable invariants

- Do not execute dependency package code, repository code, lifecycle scripts, `setup.py`, shell snippets, or generated fixtures.
- Lockfiles and SBOMs are preferred over loose manifests because they provide resolved versions and dependency paths.
- Loose manifests may create declared edges with lower confidence; they must not claim exact resolved impact unless a resolver/lockfile supplies it.
- Preserve evidence for every graph edge, source repository claim, revision claim, manifest observation, and correlation decision.
- `clean`, `suspicious`, `compromised_intrinsic`, `unknown`, and `suppressed` describe intrinsic package-version status.
- `affected_by_transitive` is a derived impact status that points to a source finding/status and impact path; it must not overwrite or masquerade as intrinsic compromise.
- Traversal output must be deterministic across runs: stable sort by depth, package ecosystem/name/version, source/manifest path, and path fingerprint.
- Traversal must be cycle-safe and bounded by configurable `max_depth` and `max_paths_per_root`.
- GitHub tokens are optional for public metadata; missing tokens must not fail public-only tests.
- Adapter logs/errors must redact tokens and avoid storing private repository contents by default.
- Future GitLab, Codeberg, Forgejo, and Gitea support is documented through interfaces only in this milestone; implement GitHub first.

---

## Current repository baseline

Existing relevant files:

- `AGENTS.md`
- `README.md`
- `docs/architecture/package-identity.md`
- `docs/architecture/artifact-identity.md`
- `docs/architecture/artifact-snapshots.md`
- `docs/architecture/hash-verification.md`
- `docs/architecture/source-correlation.md`
- `docs/integrations/adapters.md`
- `docs/development/implementation-sequence.md`
- `docs/development/testing-strategy.md`
- `docs/development/plans/01-foundation.md`
- `docs/development/plans/03-analyzer-engine.md`
- `docs/security/no-execution-policy.md`

Existing docs are intentionally high-level. This milestone must add implementation files and expand architecture docs so graph, source, and correlation behavior are testable contracts.

---

## Scope and issue map

**Dependency graph:**

- #19: Implement dependency graph schema and ingestion.
- #20: Implement transitive finding propagation.
- #65: Define dependency edge schema and confidence levels.
- #66: Implement graph cycle-safe traversal.
- #67: Implement affected-by-transitive status records.

**SCM and source correlation:**

- #21: Implement GitHub source adapter.
- #22: Correlate packages, artifacts, and source repositories.
- #68: Define source correlation confidence model.
- #69: Define SCM provider adapter interface.

**Explicitly out of scope:**

- Full dependency resolution from semver/PEP 440 ranges without lockfile/SBOM data.
- Repository cloning by default.
- GitLab, Codeberg, Forgejo, and Gitea implementations beyond interface notes and mock adapter tests.
- UI pages for graph/source views unless a previous milestone already created UI scaffolding and the parent plan expands scope.
- LLM summarization of repository contents or package READMEs.
- Alert delivery policy beyond producing affected source/package records for later notification milestones.

---

## Milestone completion gates

Run these from repository root `/home/srvadmin/workspace/ozark-security-labs/Tallow` before considering the milestone complete:

```bash
go test ./...
go test -race ./internal/graph/... ./internal/correlation/... ./internal/scm/...
make schema-validate
make generate-check
```

If analyzer or web workspaces exist from prior milestones, also run:

```bash
uv run --project analyzers pytest
uv run --project analyzers ruff check
npm --prefix web test
npm --prefix web run build
```

Expected final result:

- All commands pass.
- `git status --short` shows only intentional changes.
- `make generate-check` leaves no sqlc, OpenAPI, or schema drift.
- Dependency graph fixture ingestion is idempotent: two identical ingestions produce one stable set of nodes/edges/evidence references.
- Traversal fixture output is byte-identical across two repeated runs.
- GitHub adapter tests use `httptest`/recorded redacted fixtures only; no live network is required in unit tests.
- Docs clearly state confidence semantics, non-goals, and roadmap adapters.

---

## Dependency order

1. Expand architecture docs for graph, edge confidence, SCM adapters, and source correlation (#65, #68, #69).
2. Add migrations and sqlc queries for graph/source/correlation/status records (#19, #65, #67).
3. Add Go graph domain types and validation helpers (#19, #65).
4. Implement graph ingestion from normalized manifests/lockfiles/SBOM rows (#19).
5. Implement cycle-safe traversal (#20, #66).
6. Implement propagation and `affected_by_transitive` status records (#20, #67).
7. Define SCM adapter interface and mock adapter (#69).
8. Implement GitHub adapter (#21).
9. Implement source correlation engine and API exposure (#22, #68).
10. Wire CLI/API/scheduler entry points and final gates.

---

## Data model target

Add migrations under `db/migrations/` with names matching the repository convention. If no convention exists yet, use the next numeric prefix after existing migrations, for example:

- `db/migrations/0006_dependency_graph.up.sql`
- `db/migrations/0006_dependency_graph.down.sql`
- `db/migrations/0007_scm_sources.up.sql`
- `db/migrations/0007_scm_sources.down.sql`
- `db/migrations/0008_source_correlation.up.sql`
- `db/migrations/0008_source_correlation.down.sql`

Core tables:

- `package_versions`
  - `id uuid primary key`
  - `package_id uuid not null references packages(id)`
  - `ecosystem text not null`
  - `name_normalized text not null`
  - `version text not null`
  - `version_normalized text null`
  - `published_at timestamptz null`
  - `created_at timestamptz not null default now()`
  - Unique: `(ecosystem, name_normalized, version)`

- `dependency_edges`
  - `id uuid primary key`
  - `parent_package_version_id uuid not null references package_versions(id)`
  - `child_package_id uuid not null references packages(id)`
  - `child_package_version_id uuid null references package_versions(id)`
  - `child_ecosystem text not null`
  - `child_name_normalized text not null`
  - `constraint text null`
  - `scope text not null` enum-like check: `runtime`, `dev`, `optional`, `peer`, `build`, `test`, `unknown`
  - `relationship text not null` enum-like check: `direct`, `transitive`
  - `is_optional boolean not null default false`
  - `is_dev boolean not null default false`
  - `is_build boolean not null default false`
  - `confidence text not null` enum-like check: `resolved_lockfile`, `declared_metadata`, `inferred`
  - `source_type text not null` enum-like check: `lockfile`, `manifest`, `sbom`, `registry_metadata`, `manual`
  - `manifest_path text null`
  - `lockfile_path text null`
  - `dependency_path jsonb not null default '[]'::jsonb`
  - `evidence_refs jsonb not null default '[]'::jsonb`
  - `observed_at timestamptz not null default now()`
  - Unique fingerprint: parent, child, resolved version nullable, constraint nullable, scope, relationship, confidence, source type, manifest path, lockfile path, path hash.

- `dependency_ingestion_runs`
  - `id uuid primary key`
  - `source_kind text not null` (`registry`, `source`, `sbom`, `manual`)
  - `source_id uuid null`
  - `artifact_id uuid null`
  - `package_version_id uuid null`
  - `input_fingerprint text not null`
  - `status text not null` (`started`, `completed`, `failed`)
  - `edge_count integer not null default 0`
  - `error_code text null`
  - `error_message text null`
  - timestamps.

- `package_version_statuses`
  - `id uuid primary key`
  - `package_version_id uuid not null references package_versions(id)`
  - `status text not null` check in `clean`, `suspicious`, `compromised_intrinsic`, `unknown`, `suppressed`
  - `source_finding_id uuid null`
  - `source_analyzer_run_id uuid null`
  - `reason text not null`
  - `evidence_refs jsonb not null default '[]'::jsonb`
  - `created_at timestamptz not null default now()`
  - `suppressed_until timestamptz null`
  - Partial uniqueness for current active status if existing model uses `valid_to`; otherwise newest wins by `created_at`.

- `transitive_impact_statuses`
  - `id uuid primary key`
  - `affected_package_version_id uuid not null references package_versions(id)`
  - `source_package_version_id uuid not null references package_versions(id)`
  - `source_status_id uuid not null references package_version_statuses(id)`
  - `status text not null default 'affected_by_transitive'`
  - `depth integer not null`
  - `path jsonb not null`
  - `path_fingerprint text not null`
  - `evidence_refs jsonb not null default '[]'::jsonb`
  - `created_at timestamptz not null default now()`
  - Unique: `(affected_package_version_id, source_status_id, path_fingerprint)`

- `scm_sources`
  - `id uuid primary key`
  - `provider text not null` check in `github`, `gitlab`, `codeberg`, `forgejo`, `gitea`, `local`, `sbom`, `manual`
  - `external_id text null`
  - `web_url text not null`
  - `api_url text null`
  - `owner text null`
  - `repo text null`
  - `default_branch text null`
  - `visibility text not null default 'unknown'`
  - `last_indexed_at timestamptz null`
  - `raw_claims jsonb not null default '{}'::jsonb`
  - `created_at`, `updated_at`
  - Unique: `(provider, external_id)` where external ID present; unique normalized URL where external ID absent.

- `scm_revisions`
  - `id uuid primary key`
  - `source_id uuid not null references scm_sources(id)`
  - `commit_sha text not null`
  - `branch text null`
  - `tag text null`
  - `published_at timestamptz null`
  - `evidence_refs jsonb not null default '[]'::jsonb`
  - Unique: `(source_id, commit_sha)`.

- `source_manifests`
  - `id uuid primary key`
  - `source_id uuid not null references scm_sources(id)`
  - `revision_id uuid null references scm_revisions(id)`
  - `path text not null`
  - `ecosystem text not null`
  - `manifest_type text not null`
  - `sha256 text null`
  - `size_bytes bigint null`
  - `parsed_at timestamptz null`
  - `dependency_edge_count integer not null default 0`
  - Unique: `(source_id, revision_id, path)`.

- `source_correlations`
  - `id uuid primary key`
  - `package_version_id uuid null references package_versions(id)`
  - `artifact_id uuid null`
  - `source_id uuid not null references scm_sources(id)`
  - `revision_id uuid null references scm_revisions(id)`
  - `confidence text not null` check in `exact_metadata`, `release_tag_match`, `repository_metadata`, `manifest_observed`, `inferred_name`, `conflicting`, `unknown`
  - `score numeric(4,3) not null`
  - `evidence_refs jsonb not null default '[]'::jsonb`
  - `conflicting_source_ids jsonb not null default '[]'::jsonb`
  - `reason text not null`
  - `created_at timestamptz not null default now()`
  - Unique: `(package_version_id, artifact_id, source_id, revision_id, confidence)` with nullable-safe fingerprint if needed.

---

## Task 1: Expand dependency graph architecture docs (#65)

**Objective:** Make graph schema, edge confidence, lockfile preference, and status semantics explicit before code.

**Files:**

- Create: `docs/architecture/dependency-graph.md`
- Modify: `docs/architecture/source-correlation.md`
- Modify: `docs/development/implementation-sequence.md`

**Steps:**

1. Create `docs/architecture/dependency-graph.md` with sections:
   - Purpose.
   - Node model: package vs package version.
   - Edge model fields listed in “Data model target”.
   - Confidence levels:
     - `resolved_lockfile`: resolved version from lockfile/SBOM with path evidence.
     - `declared_metadata`: declared manifest/registry dependency range without resolver certainty.
     - `inferred`: derived from incomplete metadata or naming conventions; never exact impact by itself.
   - Relationship/scope semantics: direct/transitive, runtime/dev/optional/peer/build/test/unknown.
   - Lockfile-preferred philosophy.
   - Ingestion idempotency rules.
   - Traversal ordering and bounds.
   - Status model: intrinsic vs `affected_by_transitive`.
   - Non-goals: full solver, clone-by-default, code execution.
2. Add a short cross-link from `docs/architecture/source-correlation.md` to `docs/architecture/dependency-graph.md`.
3. Update `docs/development/implementation-sequence.md` to include this milestone after analyzer/registry prerequisites and before alerting/UI.
4. Run: `git diff -- docs/architecture/dependency-graph.md docs/architecture/source-correlation.md docs/development/implementation-sequence.md`.
5. Expected: docs contain all issue #65 acceptance criteria.

**Commit:**

```bash
git add docs/architecture/dependency-graph.md docs/architecture/source-correlation.md docs/development/implementation-sequence.md
git commit -m "docs: define dependency graph schema and confidence"
```

---

## Task 2: Expand SCM adapter and source correlation docs (#68, #69)

**Objective:** Document SCM adapter contract and source correlation confidence model before implementation.

**Files:**

- Modify: `docs/integrations/adapters.md`
- Modify: `docs/architecture/source-correlation.md`
- Create: `docs/adapters/github.md`

**Steps:**

1. In `docs/integrations/adapters.md`, replace the high-level SCM bullets with an interface contract:
   - `Provider() string`
   - `ResolveRepository(ctx, RepositoryClaim) (Repository, error)`
   - `GetRepository(ctx, RepositoryRef) (Repository, error)`
   - `GetDefaultBranch(ctx, RepositoryRef) (BranchRef, error)`
   - `ListRepositoryManifests(ctx, RepositoryRef, RevisionRef, ManifestListOptions) ([]ManifestRef, PageCursor, error)`
   - `FetchFile(ctx, RepositoryRef, RevisionRef, path, maxBytes) (FileBlob, error)`
   - `GetRevision(ctx, RepositoryRef, RevisionQuery) (Revision, error)`
   - `Poll(ctx, Cursor) ([]RepositoryEvent, Cursor, error)`
2. Add roadmap notes for GitLab, Codeberg, Forgejo, and Gitea: same interface, provider-specific auth/rate-limit/webhook details deferred.
3. In `docs/architecture/source-correlation.md`, define confidence levels:
   - `exact_metadata`: package metadata has unambiguous repo URL and revision/tag evidence.
   - `release_tag_match`: SCM tag/release matches package version after normalizer.
   - `repository_metadata`: package metadata points to repository but not revision.
   - `manifest_observed`: repository manifest/lockfile observes package/version.
   - `inferred_name`: weak name/owner heuristic only.
   - `conflicting`: multiple plausible repos or contradictory metadata.
   - `unknown`: no useful source claim.
4. Define correlation evidence schema in docs: claim type, raw claim hash, normalized URL, provider, source metadata, confidence, conflict list, created time.
5. Create `docs/adapters/github.md` documenting token-optional public mode, rate limit behavior, URL normalization, default branch/release/tag capture, and mocked test policy.
6. Run: `git diff -- docs/integrations/adapters.md docs/architecture/source-correlation.md docs/adapters/github.md`.
7. Expected: docs satisfy #68 and #69 acceptance criteria.

**Commit:**

```bash
git add docs/integrations/adapters.md docs/architecture/source-correlation.md docs/adapters/github.md
git commit -m "docs: define scm adapter and source correlation model"
```

---

## Task 3: Add dependency graph migrations and sqlc queries (#19, #65, #67)

**Objective:** Persist graph nodes, edges, ingestion runs, intrinsic statuses, and transitive impact statuses.

**Files:**

- Create: `db/migrations/0006_dependency_graph.up.sql`
- Create: `db/migrations/0006_dependency_graph.down.sql`
- Create: `db/queries/graph.sql`
- Create: `internal/graph/testdata/schema_seed.sql`
- Create: `internal/graph/store_test.go`
- Modify: `sqlc.yaml` if needed.

**Steps:**

1. Inspect existing migration prefix and adjust `0006` if needed.
2. Write failing migration/query test `internal/graph/store_test.go` that:
   - Applies migrations to a test database helper used elsewhere in the repo.
   - Inserts packages/package versions.
   - Upserts the same edge twice.
   - Asserts one row exists and evidence JSON is stable.
   - Inserts intrinsic `compromised_intrinsic` status and separate `affected_by_transitive` status.
3. Add migration with the tables listed in “Data model target”; if existing `packages`, `artifacts`, `findings`, or `analyzer_runs` schemas differ, reference existing IDs where available and document nullable fallback fields in comments.
4. Add `db/queries/graph.sql` queries:
   - `UpsertPackageVersion`
   - `GetPackageVersion`
   - `UpsertDependencyEdge`
   - `ListDependencyEdgesByParent`
   - `ListDependencyEdgesByChildPackageVersion`
   - `CreateDependencyIngestionRun`
   - `CompleteDependencyIngestionRun`
   - `FailDependencyIngestionRun`
   - `InsertPackageVersionStatus`
   - `ListPackageVersionStatuses`
   - `UpsertTransitiveImpactStatus`
   - `ListTransitiveImpactsBySourceStatus`
   - `ListTransitiveImpactsByAffectedPackage`
5. Run: `make generate` or `sqlc generate` according to repo convention.
6. Run: `go test ./internal/graph -run TestGraphStore -v`.
7. Expected failure before implementation: missing migrations/queries/types. Expected pass after implementation.
8. Run: `make generate-check`.

**Commit:**

```bash
git add db/migrations db/queries/graph.sql internal/graph/store_test.go internal/graph/testdata sqlc.yaml
git commit -m "feat: persist dependency graph schema"
```

---

## Task 4: Add graph domain types and validators (#19, #65)

**Objective:** Centralize graph enums, validation, stable fingerprints, and evidence normalization.

**Files:**

- Create: `internal/graph/types.go`
- Create: `internal/graph/validate.go`
- Create: `internal/graph/fingerprint.go`
- Create: `internal/graph/types_test.go`
- Create: `internal/graph/fingerprint_test.go`

**Steps:**

1. Write tests for:
   - Valid edge confidence values.
   - Invalid confidence rejected.
   - Scope flags match scope (`dev` sets `IsDev`, `optional` sets `IsOptional`, `build` sets `IsBuild`).
   - Stable edge fingerprint independent of input evidence order.
   - Evidence refs sorted and deduplicated.
2. Implement types:
   - `type Confidence string` constants `ConfidenceResolvedLockfile`, `ConfidenceDeclaredMetadata`, `ConfidenceInferred`.
   - `type Relationship string` constants `direct`, `transitive`.
   - `type Scope string` constants listed above.
   - `type SourceType string` constants `lockfile`, `manifest`, `sbom`, `registry_metadata`, `manual`.
   - `type PackageStatus string` constants `clean`, `suspicious`, `compromised_intrinsic`, `unknown`, `suppressed`.
   - `const AffectedByTransitiveStatus = "affected_by_transitive"` for derived records only.
3. Implement `ValidateEdge(edge Edge) error` with typed errors if available; otherwise sentinel errors in `internal/graph`.
4. Implement `CanonicalEdgeFingerprint(edge Edge) string` using normalized JSON and SHA-256. Include parent, child, resolved version, constraint, relationship, scope, confidence, source type, manifest path, lockfile path, and dependency path. Exclude timestamps and database IDs.
5. Run: `go test ./internal/graph -run 'Test(GraphTypes|EdgeFingerprint)' -v`.

**Commit:**

```bash
git add internal/graph/types.go internal/graph/validate.go internal/graph/fingerprint.go internal/graph/*_test.go
git commit -m "feat: add dependency graph domain types"
```

---

## Task 5: Implement dependency graph ingestion (#19)

**Objective:** Convert normalized lockfile/manifest/SBOM dependency observations into idempotent graph nodes and edges.

**Files:**

- Create: `internal/graph/ingest.go`
- Create: `internal/graph/ingest_test.go`
- Create: `internal/graph/testdata/npm-package-lock.json`
- Create: `internal/graph/testdata/python-poetry-lock.toml`
- Create: `internal/graph/testdata/sbom-cyclonedx.json`
- Modify: `docs/architecture/dependency-graph.md`

**Steps:**

1. Define an ingestion DTO in `internal/graph/ingest.go`:
   - `IngestionInput` with subject package version, source kind, artifact/source IDs, manifest refs, and dependency observations.
   - `DependencyObservation` with parent, child, constraint, resolved version, scope, relationship, confidence, source type, dependency path, evidence refs.
2. Write tests for:
   - Direct runtime dependency from lockfile creates parent/child/version/edge.
   - Optional dependency sets `is_optional` and `scope=optional`.
   - Dev dependency sets `is_dev` and `scope=dev`.
   - Repeated ingestion is idempotent.
   - Lockfile observation supersedes declared metadata when both describe same edge; both evidence refs may be retained, but confidence should prefer `resolved_lockfile` for resolved version edge.
   - PyPI/Poetry fixture normalizes package names through existing identity normalizer.
3. Implement `IngestDependencies(ctx, store, input) (IngestionResult, error)`:
   - Validate input.
   - Create ingestion run with stable `input_fingerprint`.
   - Upsert package versions first.
   - Upsert edges in deterministic order.
   - Complete/fail ingestion run with row count and typed error code.
4. Do not implement a full lockfile parser if prior milestones do not have one. In this task, parse minimal fixtures into `DependencyObservation` through test helper functions; production parser integration can be a later task if not already present.
5. Update docs with ingestion behavior and evidence retention.
6. Run: `go test ./internal/graph -run TestIngestDependencies -v`.
7. Run: `go test ./...`.

**Commit:**

```bash
git add internal/graph/ingest.go internal/graph/ingest_test.go internal/graph/testdata docs/architecture/dependency-graph.md
git commit -m "feat: ingest dependency graph observations"
```

---

## Task 6: Implement cycle-safe graph traversal (#20, #66)

**Objective:** Find direct and transitive dependents with deterministic ordering, path bounds, and cycle handling.

**Files:**

- Create: `internal/graph/traversal.go`
- Create: `internal/graph/traversal_test.go`
- Modify: `db/queries/graph.sql`
- Modify: generated sqlc files after `make generate`.
- Modify: `docs/architecture/dependency-graph.md`

**Steps:**

1. Write tests that seed graph fixtures:
   - Direct: `app -> badlib`.
   - Transitive: `app -> mid -> badlib`.
   - Diamond: `app -> left -> badlib` and `app -> right -> badlib`.
   - Cycle: `a -> b -> c -> a` with target `c`.
   - Path limit: more than configured path count.
   - Depth limit: deeper than configured depth.
2. Define:
   - `TraversalOptions{MaxDepth int, MaxPathsPerRoot int, IncludeDev bool, IncludeOptional bool}`.
   - `ImpactPath{Affected PackageVersionRef, Source PackageVersionRef, Depth int, Edges []EdgeRef, PathFingerprint string, EvidenceRefs []EvidenceRef}`.
3. Implement traversal by reverse edges from compromised source to dependents:
   - Use BFS for stable shortest-path-first output.
   - Track visited state as `(package_version_id, path_fingerprint)` not only node, so diamond paths are preserved.
   - Prevent cycles by rejecting paths that already contain next node.
   - Sort edge expansions by parent ecosystem/name/version, scope, relationship, edge ID/fingerprint.
   - Respect `MaxDepth` and `MaxPathsPerRoot`.
4. Add or adjust sqlc query `ListReverseDependencyEdges(child_package_version_id)`.
5. Run: `make generate`.
6. Run: `go test ./internal/graph -run TestTraverse -v`.
7. Run: `go test -race ./internal/graph/...`.
8. Update docs with traversal algorithm and bounds.

**Commit:**

```bash
git add internal/graph/traversal.go internal/graph/traversal_test.go db/queries/graph.sql docs/architecture/dependency-graph.md
git commit -m "feat: traverse dependency graph safely"
```

---

## Task 7: Implement transitive propagation and `affected_by_transitive` records (#20, #67)

**Objective:** Convert intrinsic suspicious/compromised package status into derived transitive impact records without marking dependents intrinsically malicious.

**Files:**

- Create: `internal/graph/propagation.go`
- Create: `internal/graph/propagation_test.go`
- Modify: `internal/graph/types.go`
- Modify: `db/queries/graph.sql`
- Modify: `docs/architecture/dependency-graph.md`

**Steps:**

1. Write tests for:
   - `compromised_intrinsic` on `badlib` creates `affected_by_transitive` for `app` through `mid`.
   - `suspicious` source creates lower-priority transitive impact but still points to source status.
   - `clean`, `unknown`, and `suppressed` do not create new transitive impacts.
   - Direct package `app` is not inserted into `package_version_statuses` as `compromised_intrinsic`.
   - Impact path references source status/finding ID and includes edge evidence.
   - Re-running propagation upserts, not duplicates.
2. Implement `PropagateStatus(ctx, store, sourceStatusID, options) (PropagationResult, error)`:
   - Load source intrinsic status.
   - Return no-op for statuses not in `suspicious`, `compromised_intrinsic`.
   - Traverse reverse dependents from source package version.
   - Upsert `transitive_impact_statuses` with `status='affected_by_transitive'`, depth, path JSON, path fingerprint, source status ID, source package version ID.
   - Sort output deterministically.
3. Add query `GetPackageVersionStatus`, `UpsertTransitiveImpactStatus`, and list queries if missing.
4. Run: `make generate`.
5. Run: `go test ./internal/graph -run TestPropagateStatus -v`.
6. Run: `go test ./...`.
7. Update docs with exact language: “affected by a transitive dependency with finding X,” not “this direct package is compromised.”

**Commit:**

```bash
git add internal/graph/propagation.go internal/graph/propagation_test.go internal/graph/types.go db/queries/graph.sql docs/architecture/dependency-graph.md
git commit -m "feat: record transitive dependency impact"
```

---

## Task 8: Expose graph and impact query service/API (#20, #67)

**Objective:** Provide internal service and API endpoints for listing affected dependents and source impact evidence.

**Files:**

- Create: `internal/graph/service.go`
- Create: `internal/graph/service_test.go`
- Modify: `docs/api/openapi.yaml` if API docs exist.
- Modify: `cmd/tallow-api` route wiring file if present, likely `cmd/tallow-api/main.go` or `internal/api/routes.go`.
- Create or modify: `internal/api/graph_handler.go`
- Create or modify: `internal/api/graph_handler_test.go`

**Steps:**

1. Inspect existing API route structure and use its conventions.
2. Write service tests for pagination and deterministic ordering:
   - `ListAffectedBySourceStatus(sourceStatusID, page)`.
   - `ListImpactsForPackageVersion(packageVersionID, page)`.
3. Implement service methods using sqlc list queries.
4. If API exists, add endpoints:
   - `GET /v1/package-versions/{id}/statuses`
   - `GET /v1/package-versions/{id}/transitive-impacts`
   - `GET /v1/statuses/{id}/affected-dependents`
5. Response records must include:
   - Affected package/version.
   - Source package/version.
   - `status: affected_by_transitive`.
   - Source status/finding ID.
   - Depth.
   - Path package/version chain.
   - Evidence refs.
6. Add OpenAPI examples if `docs/api/openapi.yaml` exists.
7. Run targeted API tests, for example: `go test ./internal/api -run TestGraphHandlers -v`.
8. Run: `go test ./...`.

**Commit:**

```bash
git add internal/graph/service.go internal/graph/service_test.go internal/api docs/api/openapi.yaml cmd/tallow-api
git commit -m "feat: expose transitive impact queries"
```

---

## Task 9: Add SCM adapter interface and mock adapter (#69)

**Objective:** Define provider-neutral SCM interfaces and prove they can support GitHub now and GitLab/Codeberg/Forgejo/Gitea later.

**Files:**

- Create: `internal/scm/types.go`
- Create: `internal/scm/adapter.go`
- Create: `internal/scm/errors.go`
- Create: `internal/scm/mock/adapter.go`
- Create: `internal/scm/mock/adapter_test.go`
- Modify: `docs/integrations/adapters.md`

**Steps:**

1. Define types:
   - `Provider` constants: `github`, `gitlab`, `codeberg`, `forgejo`, `gitea`.
   - `RepositoryClaim{URL, Owner, Repo, ProviderHint, PackageEcosystem, PackageName, EvidenceRefs}`.
   - `RepositoryRef{Provider, ExternalID, Owner, Repo, URL}`.
   - `Repository{Ref, DefaultBranch, Visibility, WebURL, APIURL, Topics, EvidenceRefs, RawClaims}`.
   - `RevisionRef{CommitSHA, Branch, Tag}`.
   - `ManifestRef{Path, Ecosystem, Type, SizeBytes, SHA256}`.
   - `FileBlob{Path, Revision, SizeBytes, SHA256, Content []byte}` with max size enforced by adapters.
   - `Cursor` and `RepositoryEvent` for polling.
2. Define interface exactly:
   ```go
   type Adapter interface {
       Provider() Provider
       ResolveRepository(ctx context.Context, claim RepositoryClaim) (Repository, error)
       GetRepository(ctx context.Context, ref RepositoryRef) (Repository, error)
       GetDefaultBranch(ctx context.Context, ref RepositoryRef) (RevisionRef, error)
       ListRepositoryManifests(ctx context.Context, ref RepositoryRef, rev RevisionRef, opts ManifestListOptions) ([]ManifestRef, Cursor, error)
       FetchFile(ctx context.Context, ref RepositoryRef, rev RevisionRef, path string, maxBytes int64) (FileBlob, error)
       GetRevision(ctx context.Context, ref RepositoryRef, query RevisionQuery) (RevisionRef, error)
       Poll(ctx context.Context, cursor Cursor) ([]RepositoryEvent, Cursor, error)
   }
   ```
3. Add typed errors in `internal/scm/errors.go`: `ErrNotFound`, `ErrRateLimited`, `ErrUnauthorized`, `ErrForbidden`, `ErrTemporary`, `ErrInvalidResponse`, `ErrUnsupported` with wrappers carrying retry time where applicable.
4. Implement `internal/scm/mock.Adapter` with in-memory maps and deterministic ordering.
5. Write mock tests verifying interface behavior, manifest fetch size limits, polling cursor, typed errors, and deterministic list ordering.
6. Run: `go test ./internal/scm/... -v`.

**Commit:**

```bash
git add internal/scm docs/integrations/adapters.md
git commit -m "feat: define scm adapter interface"
```

---

## Task 10: Implement GitHub URL normalization and repo claim extraction (#21)

**Objective:** Resolve GitHub repository references from npm/PyPI metadata and common GitHub URL forms without network calls.

**Files:**

- Create: `internal/scm/github/normalize.go`
- Create: `internal/scm/github/normalize_test.go`
- Create: `internal/scm/github/metadata.go`
- Create: `internal/scm/github/metadata_test.go`
- Modify: `docs/adapters/github.md`

**Steps:**

1. Write tests for accepted URL forms:
   - `https://github.com/owner/repo`
   - `https://github.com/owner/repo.git`
   - `git+https://github.com/owner/repo.git`
   - `git://github.com/owner/repo.git`
   - `ssh://git@github.com/owner/repo.git`
   - `git@github.com:owner/repo.git`
   - URLs with `/tree/main`, `/commit/<sha>`, `/releases/tag/v1.2.3` should normalize to repo plus revision hint.
2. Write rejection tests for non-GitHub URLs, path traversal, missing owner/repo, and suspicious control characters.
3. Implement `NormalizeRepositoryURL(raw string) (RepositoryClaim, error)` with no shelling out.
4. Implement package metadata extraction helpers:
   - `ClaimsFromNPMMetadata(map[string]any)` reads `repository.url`, `homepage`, `bugs.url` only as evidence; prefer `repository.url`.
   - `ClaimsFromPyPIMetadata(map[string]any)` reads `project_urls`, `home_page`, `download_url`; prefer explicit repository/source labels.
5. Tests must verify ambiguity: multiple conflicting GitHub URLs produce multiple claims or `conflicting` marker, not a single certain claim.
6. Run: `go test ./internal/scm/github -run 'TestNormalize|TestClaims' -v`.

**Commit:**

```bash
git add internal/scm/github/normalize.go internal/scm/github/normalize_test.go internal/scm/github/metadata.go internal/scm/github/metadata_test.go docs/adapters/github.md
git commit -m "feat: normalize github source claims"
```

---

## Task 11: Implement GitHub adapter HTTP client (#21)

**Objective:** Fetch GitHub repository metadata, default branches, revisions, releases/tags, and manifest files through bounded API calls.

**Files:**

- Create: `internal/scm/github/client.go`
- Create: `internal/scm/github/adapter.go`
- Create: `internal/scm/github/adapter_test.go`
- Create: `internal/scm/github/testdata/repo.json`
- Create: `internal/scm/github/testdata/tags.json`
- Create: `internal/scm/github/testdata/contents-package-json.json`
- Modify: `docs/adapters/github.md`

**Steps:**

1. Write `httptest` tests for:
   - Public repository with no token returns repo metadata and default branch.
   - Token is sent as `Authorization: Bearer <token>` when configured, but logs/errors redact it.
   - `404` maps to `scm.ErrNotFound`.
   - `403` with rate limit headers maps to `scm.ErrRateLimited` and retry time.
   - Private/missing repo is handled gracefully.
   - Malformed JSON maps to `scm.ErrInvalidResponse`.
   - File response exceeding `maxBytes` returns typed size error without storing content.
   - Default branch and tag/release revision queries are deterministic.
2. Implement `Client` with:
   - Base URL override for tests.
   - HTTP timeout.
   - Max response bytes.
   - Redirect policy that rejects private IP redirects unless explicit config exists.
   - User-Agent `tallow/<version>`.
3. Implement adapter methods from `internal/scm.Adapter`.
4. Manifest listing should fetch likely root files by API contents calls for this milestone:
   - `package-lock.json`, `npm-shrinkwrap.json`, `package.json`.
   - `poetry.lock`, `requirements.txt`, `pyproject.toml`.
   - `bom.json`, `bom.xml`, `sbom.json`.
   Do not recursively crawl the whole repo in this milestone.
5. Run: `go test ./internal/scm/github -v`.
6. Run: `go test ./internal/scm/... -v`.

**Commit:**

```bash
git add internal/scm/github docs/adapters/github.md
git commit -m "feat: implement github scm adapter"
```

---

## Task 12: Add SCM/source persistence queries (#21, #22, #68)

**Objective:** Persist repositories, revisions, manifests, and source correlations with confidence/evidence.

**Files:**

- Create: `db/migrations/0007_scm_sources.up.sql`
- Create: `db/migrations/0007_scm_sources.down.sql`
- Create: `db/migrations/0008_source_correlation.up.sql`
- Create: `db/migrations/0008_source_correlation.down.sql`
- Create: `db/queries/scm.sql`
- Create: `db/queries/correlation.sql`
- Create: `internal/correlation/store_test.go`
- Modify: `sqlc.yaml` if needed.

**Steps:**

1. Write failing store tests that:
   - Upsert a GitHub source twice and assert one row.
   - Upsert revisions by source + commit SHA.
   - Upsert manifest by source + revision + path.
   - Insert correlations with `exact_metadata`, `conflicting`, and `unknown` confidence.
   - List correlations by package version and artifact ID in deterministic order.
2. Add migrations using tables from “Data model target”.
3. Add sqlc queries:
   - `UpsertSCMSource`
   - `GetSCMSourceByProviderExternalID`
   - `GetSCMSourceByURL`
   - `UpsertSCMRevision`
   - `UpsertSourceManifest`
   - `UpsertSourceCorrelation`
   - `ListSourceCorrelationsByPackageVersion`
   - `ListSourceCorrelationsByArtifact`
   - `ListManifestsBySource`
4. Run: `make generate`.
5. Run: `go test ./internal/correlation -run TestCorrelationStore -v`.
6. Run: `make generate-check`.

**Commit:**

```bash
git add db/migrations db/queries/scm.sql db/queries/correlation.sql internal/correlation/store_test.go sqlc.yaml
git commit -m "feat: persist scm sources and correlations"
```

---

## Task 13: Implement source correlation engine (#22, #68)

**Objective:** Link package versions/artifacts to likely source repositories/revisions using confidence-scored evidence without overstating ambiguity.

**Files:**

- Create: `internal/correlation/types.go`
- Create: `internal/correlation/correlate.go`
- Create: `internal/correlation/confidence.go`
- Create: `internal/correlation/correlate_test.go`
- Create: `internal/correlation/testdata/npm-package-metadata.json`
- Create: `internal/correlation/testdata/pypi-project-metadata.json`
- Modify: `docs/architecture/source-correlation.md`

**Steps:**

1. Define `CorrelationInput` with package version ref, artifact ref, metadata claims, registry evidence refs, optional SCM adapter, and optional observed source manifests.
2. Define `CorrelationResult` containing source ref, revision ref, confidence, score, evidence refs, conflicts, and reason.
3. Write tests for acceptance cases:
   - Exact npm repository URL + GitHub release tag matching version => `exact_metadata` or `release_tag_match` with high score.
   - PyPI project URL labeled “Source” resolves to GitHub repo => `repository_metadata` if no revision.
   - Missing metadata => `unknown` result with evidence that no source claim exists.
   - Multiple conflicting GitHub URLs => `conflicting`; do not pick one as certain.
   - Manifest-observed package/version in repo lockfile => `manifest_observed`.
4. Implement confidence scoring deterministic rules:
   - `exact_metadata`: `1.000` when repo URL and immutable revision/tag match package version or artifact source claim.
   - `release_tag_match`: `0.900` when repository metadata plus tag/release version match.
   - `repository_metadata`: `0.700` when repo URL is explicit but no revision.
   - `manifest_observed`: `0.650` when source manifest contains package/version, not necessarily package's own source.
   - `inferred_name`: `0.300` max.
   - `conflicting`: `0.100` and include conflicts.
   - `unknown`: `0.000`.
5. Ensure raw metadata is not stored verbatim unless existing evidence storage supports bounded redacted blobs; otherwise store hashes and claim paths.
6. Run: `go test ./internal/correlation -run TestCorrelate -v`.
7. Update docs with examples and non-goals.

**Commit:**

```bash
git add internal/correlation/types.go internal/correlation/correlate.go internal/correlation/confidence.go internal/correlation/correlate_test.go internal/correlation/testdata docs/architecture/source-correlation.md
git commit -m "feat: correlate packages with source repositories"
```

---

## Task 14: Wire GitHub source resolution into correlation workflow (#21, #22)

**Objective:** Use the GitHub adapter to enrich package metadata claims and persist source/correlation records.

**Files:**

- Create: `internal/correlation/service.go`
- Create: `internal/correlation/service_test.go`
- Modify: `internal/scm/github/adapter.go`
- Modify: scheduler/job wiring if present, likely `internal/scheduler/`.
- Modify: CLI if present, likely `cmd/tallow/`.

**Steps:**

1. Write service tests using `internal/scm/mock.Adapter`:
   - Successful GitHub resolution persists `scm_sources`, `scm_revisions`, and `source_correlations`.
   - Missing/private repo persists `unknown` or low-confidence record with typed error evidence, not fatal ingestion failure.
   - Rate-limited repo marks retryable error if scheduler jobs exist.
   - Conflicting claims produce one `conflicting` result with conflict evidence.
2. Implement `Service.CorrelatePackageVersion(ctx, packageVersionID, metadata EvidenceReader)`:
   - Load package/artifact metadata from existing stores.
   - Extract GitHub claims.
   - Resolve repos through adapter if provider is GitHub.
   - Persist source/revision/manifest rows where available.
   - Persist correlation rows.
3. If scheduler exists, add a job handler for source correlation after artifact/package observation. Keep handler idempotent.
4. If CLI exists, add a diagnostic command:
   - `tallow source correlate --ecosystem npm --package <name> --version <version>`
   - Output confidence, repo URL, revision, evidence refs.
   - Do not require token for public metadata.
5. Run targeted tests:
   - `go test ./internal/correlation -run TestCorrelationService -v`
   - `go test ./internal/scm/github -v`
6. Run: `go test ./...`.

**Commit:**

```bash
git add internal/correlation internal/scm/github internal/scheduler cmd/tallow
git commit -m "feat: wire source correlation workflow"
```

---

## Task 15: Expose source correlation API evidence (#22, #68)

**Objective:** Make package/artifact/source correlation evidence visible to API consumers without leaking private contents.

**Files:**

- Modify: `docs/api/openapi.yaml` if API docs exist.
- Create or modify: `internal/api/correlation_handler.go`
- Create or modify: `internal/api/correlation_handler_test.go`
- Modify: route wiring file used by API service.

**Steps:**

1. Write handler tests for:
   - `GET /v1/package-versions/{id}/source-correlations` returns deterministic list.
   - `GET /v1/artifacts/{id}/source-correlations` returns deterministic list.
   - Conflicting correlation includes `conflicting_source_ids` and reason.
   - Unknown correlation does not include raw private metadata.
2. Implement handlers using correlation store/service.
3. Response fields:
   - `source.provider`, `source.url`, `source.owner`, `source.repo`, `source.default_branch`.
   - `revision.commit_sha`, `revision.tag`, `revision.branch` if known.
   - `confidence`, `score`, `reason`.
   - `evidence_refs`.
   - `conflicts` for conflicting metadata.
4. Update OpenAPI schemas/examples.
5. Run: `go test ./internal/api -run TestCorrelationHandlers -v`.
6. Run: `go test ./...`.

**Commit:**

```bash
git add internal/api docs/api/openapi.yaml
git commit -m "feat: expose source correlation evidence"
```

---

## Task 16: Add schema fixtures and contract validation (#19, #22, #67, #68)

**Objective:** Add JSON examples/schemas for graph edges, transitive impact, SCM source, and correlation API payloads if the repository has schema validation scaffolding.

**Files:**

- Create: `schemas/dependency-edge.schema.json`
- Create: `schemas/transitive-impact.schema.json`
- Create: `schemas/scm-source.schema.json`
- Create: `schemas/source-correlation.schema.json`
- Create: `schemas/examples/dependency-edge.lockfile.npm.json`
- Create: `schemas/examples/transitive-impact.npm.json`
- Create: `schemas/examples/source-correlation.github.json`
- Modify: `scripts/validate_schemas.py` or `scripts/validate-schemas.sh` if present.
- Modify: `.github/workflows/ci.yml` if present.

**Steps:**

1. Inspect existing schema style and use it.
2. Write strict schemas with `additionalProperties: false` unless existing conventions differ.
3. Ensure enums match Go constants exactly:
   - statuses: intrinsic statuses plus separate `affected_by_transitive` only in transitive impact schema.
   - confidence enums for graph and source correlation.
4. Add examples for lockfile edge, transitive impact path, and GitHub correlation.
5. Add validation script entries.
6. Run: `make schema-validate`.
7. Run: `go test ./...`.

**Commit:**

```bash
git add schemas scripts .github/workflows/ci.yml
git commit -m "test: add graph and source correlation contract fixtures"
```

---

## Task 17: Add end-to-end milestone integration tests (#19-#22, #65-#69)

**Objective:** Prove the milestone works as one deterministic flow from dependency ingestion to propagation and source correlation.

**Files:**

- Create: `internal/integration/dependency_graph_scm_test.go`
- Create: `testdata/integration/npm-app/package-lock.json`
- Create: `testdata/integration/npm-app/package.json`
- Create: `testdata/integration/github/repo.json`
- Create: `testdata/integration/github/tags.json`

**Steps:**

1. Write integration test with local database helper and mock GitHub adapter:
   - Ingest package version `badlib@1.2.3` and app dependency graph from lockfile.
   - Insert intrinsic `compromised_intrinsic` status for `badlib@1.2.3` with fake finding ID.
   - Propagate status.
   - Assert app package version has exactly one `affected_by_transitive` impact path and no intrinsic compromised status.
   - Correlate `badlib@1.2.3` metadata to GitHub repo `owner/badlib` and tag `v1.2.3`.
   - Assert source correlation confidence and evidence refs.
2. Ensure fixture content is harmless and does not include executable malicious payloads.
3. Run: `go test ./internal/integration -run TestDependencyGraphSCMMilestone -v`.
4. Run twice and compare stable output if test writes golden JSON.
5. Run: `go test ./...`.

**Commit:**

```bash
git add internal/integration/dependency_graph_scm_test.go testdata/integration
git commit -m "test: cover dependency graph scm milestone flow"
```

---

## Task 18: Update CI and final documentation gates

**Objective:** Ensure graph, SCM, correlation, schema, and race tests run in CI and docs describe final operator-visible behavior.

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `docs/development/testing-strategy.md`
- Modify: `README.md`
- Modify: `docs/architecture/dependency-graph.md`
- Modify: `docs/architecture/source-correlation.md`
- Modify: `docs/integrations/adapters.md`
- Modify: `docs/adapters/github.md`

**Steps:**

1. Add CI jobs/steps:
   - `go test ./...`
   - `go test -race ./internal/graph/... ./internal/correlation/... ./internal/scm/...`
   - `make schema-validate`
   - `make generate-check`
2. Update testing strategy with fixture categories:
   - graph fixtures
   - traversal fixtures
   - SCM adapter HTTP fixtures
   - source correlation ambiguity fixtures
3. Update README capability list with dependency graph and GitHub source correlation if project README tracks milestones.
4. Run final gates:
   ```bash
   go test ./...
   go test -race ./internal/graph/... ./internal/correlation/... ./internal/scm/...
   make schema-validate
   make generate-check
   ```
5. If analyzer/web workspaces exist:
   ```bash
   uv run --project analyzers pytest
   uv run --project analyzers ruff check
   npm --prefix web test
   npm --prefix web run build
   ```
6. Run: `git status --short`.
7. Expected: only intentional files changed, all tests pass.

**Commit:**

```bash
git add .github/workflows/ci.yml docs README.md
git commit -m "ci: add dependency graph scm milestone gates"
```

---

## Acceptance checklist by issue

### #19: Implement dependency graph schema and ingestion

- [ ] `db/migrations/*dependency_graph*.sql` creates package version nodes and dependency edges.
- [ ] `db/queries/graph.sql` supports idempotent upserts and list queries.
- [ ] `internal/graph/ingest.go` ingests normalized dependency observations.
- [ ] Edges include scope/type/confidence/evidence.
- [ ] npm and PyPI fixture observations normalize names where practical.
- [ ] Tests cover direct, optional, dev, and repeated ingestion.

### #20: Implement transitive finding propagation

- [ ] `internal/graph/traversal.go` identifies direct and transitive dependents.
- [ ] `internal/graph/propagation.go` creates derived impact records.
- [ ] Impact paths preserve depth, ordered path, path fingerprint, and evidence.
- [ ] Cycles handled safely.
- [ ] Results deterministic and paginated.
- [ ] Tests cover direct, transitive, diamond, and cyclic graphs.

### #21: Implement GitHub source adapter

- [ ] `internal/scm/github` resolves repo refs from npm/PyPI metadata.
- [ ] Adapter captures repo URL, default branch, tags/releases/revisions where relevant.
- [ ] Missing/private/rate-limited repos map to typed errors and do not crash correlation.
- [ ] Token optional for public use.
- [ ] Mocked `httptest` GitHub tests included.

### #22: Correlate packages, artifacts, and source repositories

- [ ] `internal/correlation` stores confidence and evidence.
- [ ] Ambiguity is represented as `conflicting`/`unknown`, not certainty.
- [ ] API exposes correlation evidence.
- [ ] Tests cover exact, missing, multiple, and conflicting evidence.
- [ ] Docs explain non-goals.

### #65: Define dependency edge schema and confidence levels

- [ ] `docs/architecture/dependency-graph.md` defines edge schema.
- [ ] Edges store parent, child, constraint, resolved version, scope, optional/dev/build flags.
- [ ] Confidence enum includes `resolved_lockfile`, `declared_metadata`, `inferred`.
- [ ] Migration/sqlc tests pass.
- [ ] Docs explain lockfile-preferred philosophy.

### #66: Implement graph cycle-safe traversal

- [ ] Traversal handles direct, transitive, diamond, and cyclic graphs.
- [ ] Depth and path count limits configurable.
- [ ] Deterministic path ordering.
- [ ] Tests cover cycle and diamond cases.

### #67: Implement affected-by-transitive status records

- [ ] Intrinsic package statuses and `affected_by_transitive` records are stored separately.
- [ ] Impact path references source status/finding ID.
- [ ] API can list affected direct dependencies.
- [ ] Tests prove direct package is not marked intrinsically malicious.

### #68: Define source correlation confidence model

- [ ] `docs/architecture/source-correlation.md` documents confidence levels.
- [ ] Conflicting metadata handled without certainty claims.
- [ ] Correlation evidence schema defined.
- [ ] Tests planned and implemented for exact/missing/multiple candidates.

### #69: Define SCM provider adapter interface

- [ ] `internal/scm.Adapter` supports repo resolution, manifest fetch, revision metadata, and cursor polling.
- [ ] GitHub adapter conforms.
- [ ] Future GitLab/Codeberg/Forgejo/Gitea methods documented only.
- [ ] Mock adapter tests exist.

---

## Final verification commands

Run from `/home/srvadmin/workspace/ozark-security-labs/Tallow`:

```bash
go test ./...
go test -race ./internal/graph/... ./internal/correlation/... ./internal/scm/...
make schema-validate
make generate-check
git status --short
```

Optional if workspaces exist:

```bash
uv run --project analyzers pytest
uv run --project analyzers ruff check
npm --prefix web test
npm --prefix web run build
```

Expected final output:

- Go tests pass.
- Race tests pass.
- Schema validation passes.
- Generated files are clean.
- Git status shows only reviewed milestone changes.

---

## Implementation notes for subagents

- Keep PRs/task commits small and independently testable.
- Use existing repository conventions if filenames/package names differ; update this plan's exact paths only if prior milestones created authoritative alternatives.
- Prefer adding narrow adapters/services over broad rewrites.
- Do not introduce network-dependent unit tests.
- Do not execute artifact or repository code while parsing manifests or fixtures.
- Treat all metadata strings as untrusted evidence: validate, bound, normalize, and redact.
- If a contract gap appears, update the linked docs in the same commit as the implementation.
