# Foundation Milestone Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build Tallow's Foundation milestone: local development stack, Go API/CLI skeletons, PostgreSQL/sqlc persistence, NATS JetStream event spine, identity and schema contracts, scheduler leases, security docs, metrics, and CI contract gates for issues #2-#8, #31-#40, #70, #85, and #88.

**Architecture:** Implement the deterministic evidence spine before analyzers, UI, and LLM features. The Go control plane owns configuration, HTTP API, CLI, database access, event publishing/consuming, identity normalization, scheduler leases, metrics, and typed errors. PostgreSQL is the source of truth, NATS JetStream is the durable event bus, schemas define public contracts before producers/consumers depend on them, and local Docker Compose starts only unprivileged development services.

**Tech Stack:** Go 1.23+, chi, pgx, sqlc, golang-migrate, slog, NATS JetStream, PostgreSQL, Prometheus client_golang, JSON Schema, GitHub Actions, Docker Compose, Apache-2.0 monorepo.

---

## Scope and Issue Map

**Foundation P0/P1 issues covered directly:**
- #2: Docker Compose local development stack.
- #3: Go API skeleton with chi, slog, config, and health endpoints.
- #4: PostgreSQL migrations with golang-migrate, pgx, and sqlc.
- #5: NATS JetStream event bus integration.
- #6: Standalone `tallow` CLI skeleton.
- #7: Initial threat model and security boundaries.
- #8: Prometheus metrics and operational diagnostics.
- #31: Canonical package identity model.
- #32: Canonical artifact identity model.
- #33: Ecosystem name normalizers.
- #34: Version normalization boundaries.
- #35: Identity fixture corpus.
- #36: Event envelope JSON Schema.
- #37: Artifact observation event schema.
- #38: Evidence reference schema.
- #39: Typed error catalog.
- #40: Request ID propagation contract.
- #70: Scheduler job model and leases.
- #85: Repository self-protection checklist workflow.
- #88: Generated contract drift checks.

**Explicitly out of scope for this milestone:**
- Registry adapters beyond contract fixtures.
- Artifact download, hash verification implementation, and safe unpack implementation beyond schemas/docs/errors.
- Python analyzer worker execution.
- React UI.
- LLM summaries.
- Cloud/S3, Helm, production auth, notification delivery.

---

## Foundation Gates

Do not close this milestone until all gates pass.

### Functional gates
- `docker compose up -d postgres nats` starts local PostgreSQL and NATS JetStream with health checks.
- `go run ./cmd/tallow-api` starts an API server with `/healthz`, `/readyz`, and `/metrics`.
- `go run ./cmd/tallow --help` prints help and exits `0`.
- `go run ./cmd/tallow db migrate --config configs/tallow.example.yml` applies migrations to an empty local database.
- NATS readiness checks verify JetStream, not just TCP connectivity.
- The scheduler lease query prevents duplicate job acquisition by two workers.

### Contract gates
- JSON Schemas exist for the event envelope, artifact observation event, evidence references, and analyzer finding output.
- Golden valid and invalid fixtures exist under `schemas/testdata/`.
- Contract validation rejects unknown event major versions and absolute evidence paths.
- `make generate` followed by `git diff --exit-code` is clean.
- CI fails with an actionable message when generated sqlc output or schema fixtures drift.

### Safety gates
- No package code is executed in tests, fixtures, CLI, API, Docker Compose, or docs examples.
- All package metadata, artifact paths, README text, diffs, and maintainer text are treated as hostile input.
- No default Compose service runs privileged or mounts the Docker socket.
- Logs and metrics never include artifact contents, snippets, registry credentials, or raw hostile payloads.
- LLM features remain disabled/not implemented; docs state that deterministic scoring owns severity.

### Test gates
- `go test ./...`
- `go test -race ./internal/scheduler/...`
- `go test -tags=integration ./...` when Docker services are available.
- `make schema-validate`
- `make generate-check`
- `docker compose config`
- `docker compose up -d postgres nats && docker compose ps && docker compose down -v`

---

## Dependency Order

1. Repository build/test scaffolding and CI (#85, #88 prerequisites).
2. Configuration package (#3, #2, #4, #5, #6, #8).
3. Docker Compose local services (#2).
4. API skeleton, typed errors, request IDs, and metrics foundations (#3, #8, #39, #40).
5. Database migrations, sqlc, and storage docs (#4).
6. Identity models, normalizers, version boundaries, and fixtures (#31-#35).
7. Event schemas and NATS helpers (#5, #36, #37, #38, #40).
8. Scheduler job model and leases (#70).
9. CLI skeleton and migration command (#6).
10. Security docs and release self-protection workflow (#7, #85).
11. Final contract drift checks, docs links, and milestone verification (#88).

---

## Task 1: Add Build, Generate, and Validation Scaffolding

**Objective:** Establish repeatable commands for tests, generation, schema validation, and local service checks.

**Issues:** #85, #88.

**Files:**
- Create: `Makefile`
- Create: `scripts/validate-schemas.sh`
- Create: `scripts/generate-check.sh`
- Create: `.github/workflows/ci.yml`
- Modify: `docs/development/testing-strategy.md`

**Steps:**
1. Create `Makefile` with targets:
   - `test`: `go test ./...`
   - `test-integration`: `go test -tags=integration ./...`
   - `test-race`: `go test -race ./internal/scheduler/...`
   - `generate`: `go generate ./...` and `sqlc generate`
   - `generate-check`: run generation, then `git diff --exit-code`
   - `schema-validate`: run `scripts/validate-schemas.sh`
   - `compose-check`: `docker compose config`
2. Create `scripts/validate-schemas.sh` with `set -euo pipefail`; initially print a clear skip if no schemas exist, then later update to validate all fixtures once schemas land.
3. Create `scripts/generate-check.sh` with `set -euo pipefail`, `make generate`, and an actionable diff failure message.
4. Add `.github/workflows/ci.yml` jobs for Go tests, schema validation, generation drift, Docker Compose config, and security docs existence.
5. Update `docs/development/testing-strategy.md` with `make` commands and drift expectations.
6. Run `make test`, `make schema-validate`, `make generate-check`, and `make compose-check` after later tasks add required files.

**Verification:**
```bash
make schema-validate
make generate-check
```
Expected: both commands exit `0`; before schemas/sqlc are introduced they may report explicit no-op messages, not silent success.

**Commit:**
```bash
git add Makefile scripts/ .github/workflows/ci.yml docs/development/testing-strategy.md
git commit -m "ci: add foundation validation scaffolding"
```

---

## Task 2: Initialize Go Module and Shared Version Package

**Objective:** Create the minimal Go module layout used by API, CLI, database, events, scheduler, and tests.

**Issues:** #3, #6.

**Files:**
- Create: `go.mod`
- Create: `internal/version/version.go`
- Create: `internal/version/version_test.go`

**Steps:**
1. Run `go mod init github.com/Ozark-Security-Labs/Tallow` if `go.mod` does not already exist.
2. Add `internal/version/version.go` with exported build variables:
   - `Version = "dev"`
   - `Commit = "unknown"`
   - `Date = "unknown"`
3. Add `internal/version.Info()` returning a deterministic struct with `version`, `commit`, and `date` JSON fields.
4. Add unit tests asserting default values are non-empty and JSON field names are stable.
5. Run `gofmt` and `go test ./internal/version`.

**Verification:**
```bash
go test ./internal/version
```
Expected: version package tests pass.

**Commit:**
```bash
git add go.mod go.sum internal/version/
git commit -m "chore: initialize go module"
```

---

## Task 3: Implement Configuration Loading

**Objective:** Add explicit environment/default configuration for API, CLI, database, NATS, metrics, and filesystem storage.

**Issues:** #2, #3, #4, #5, #6, #8.

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `configs/tallow.example.yml`
- Create: `.env.example`
- Modify: `README.md`

**Steps:**
1. Define `config.Config` with nested structs:
   - `Server.ListenAddress`, default `127.0.0.1:8844`.
   - `Postgres.DSN`, default `postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable`.
   - `NATS.URL`, default `nats://localhost:4222`.
   - `Storage.Root`, default `./var/tallow/storage`.
   - `Metrics.Enabled`, default `true`.
   - `Log.Level`, default `info`.
2. Implement `Load(env map[string]string) (Config, error)` for deterministic tests and `LoadFromEnvironment()` for production.
3. Support environment variables with `TALLOW_` prefix, including `TALLOW_SERVER_LISTEN`, `TALLOW_POSTGRES_DSN`, `TALLOW_NATS_URL`, `TALLOW_STORAGE_ROOT`, `TALLOW_METRICS_ENABLED`, and `TALLOW_LOG_LEVEL`.
4. Validate required URLs/DSNs are non-empty and storage root is not `/`.
5. Create `.env.example` and `configs/tallow.example.yml` with local defaults only; no cloud credentials.
6. Update README quickstart paths if needed.
7. Add tests for defaults, overrides, boolean parsing, invalid storage root, and invalid log level.

**Verification:**
```bash
go test ./internal/config
```
Expected: config tests pass.

**Commit:**
```bash
git add internal/config/ configs/tallow.example.yml .env.example README.md
git commit -m "feat: add foundation configuration"
```

---

## Task 4: Add Docker Compose Local Development Stack

**Objective:** Provide reproducible local PostgreSQL, NATS JetStream, API, worker placeholder, UI placeholder, and filesystem storage wiring without cloud credentials or privileged services.

**Issues:** #2, #85.

**Files:**
- Create: `docker-compose.yml`
- Create: `Dockerfile`
- Create: `docs/development/local-setup.md`
- Modify: `.env.example`
- Modify: `docs/security/release-self-protection.md`

**Steps:**
1. Add `docker-compose.yml` with services:
   - `postgres`: `postgres:16-alpine`, local credentials from `.env`, healthcheck `pg_isready`.
   - `nats`: `nats:2-alpine`, command enabling JetStream (`-js`), healthcheck against monitoring endpoint or CLI where available.
   - `api`: build local `Dockerfile`, command `tallow-api`, depends on healthy Postgres/NATS, mount `./var/tallow/storage:/var/lib/tallow/storage`.
   - `worker`: same image, command placeholder that exits with a clear message until workers exist; do not make it required for default startup.
   - `web`: profile-gated placeholder for future React UI, not started by default.
2. Add named volumes for PostgreSQL and NATS data.
3. Add `TALLOW_STORAGE_ROOT=/var/lib/tallow/storage` to Compose environment.
4. Ensure no service uses `privileged: true`, host networking, or Docker socket mounts.
5. Create `Dockerfile` using multi-stage Go build; initially build `cmd/tallow-api` and `cmd/tallow` once those exist.
6. Document startup, reset, logs, troubleshooting, and no-cloud-credentials policy in `docs/development/local-setup.md`.
7. Update `docs/security/release-self-protection.md` to state default Compose must remain unprivileged.
8. Run `docker compose config`.

**Verification:**
```bash
docker compose config
docker compose up -d postgres nats
docker compose ps
docker compose down -v
```
Expected: config validates; Postgres and NATS reach healthy/running state; teardown removes local volumes.

**Commit:**
```bash
git add docker-compose.yml Dockerfile .env.example docs/development/local-setup.md docs/security/release-self-protection.md
git commit -m "feat: add local docker compose stack"
```

---

## Task 5: Implement Typed Error Catalog

**Objective:** Define safe, stable error codes and a JSON error envelope for API, CLI, logs, and tests.

**Issues:** #39, supports #3, #7, #8.

**Files:**
- Create: `internal/tallowerr/errors.go`
- Create: `internal/tallowerr/errors_test.go`
- Create: `docs/development/error-catalog.md`
- Modify: `docs/development/testing-strategy.md`
- Modify: `docs/security/safe-unpack.md`

**Steps:**
1. Define `type Code string` with at least:
   - `validation_failed`
   - `auth_failed`
   - `hash_mismatch`
   - `unpack_rejected`
   - `analyzer_failed`
   - `registry_unavailable`
   - `database_unavailable`
   - `event_bus_unavailable`
   - `internal_error`
2. Define `type Error struct { Code Code; Message string; SafeDetail string; Cause error }`.
3. Implement `Error()`, `Unwrap()`, `IsCode(err, code)`, and `HTTPStatus(code)`.
4. Define API envelope shape:
   - `error.code`
   - `error.message`
   - `error.request_id`
   - optional `error.details` with safe bounded values only.
5. Add tests for wrapping, code matching, HTTP status mapping, and JSON-safe fields.
6. Document every code in `docs/development/error-catalog.md` and link from testing strategy.
7. Add `unpack_rejected` references to `docs/security/safe-unpack.md`.

**Verification:**
```bash
go test ./internal/tallowerr
```
Expected: error catalog tests pass.

**Commit:**
```bash
git add internal/tallowerr/ docs/development/error-catalog.md docs/development/testing-strategy.md docs/security/safe-unpack.md
git commit -m "feat: define typed error catalog"
```

---

## Task 6: Implement Request ID Propagation Primitives

**Objective:** Provide request ID generation, context storage, response headers, slog attributes, and later event trace propagation.

**Issues:** #40, supports #3, #5, #8, #39.

**Files:**
- Create: `internal/requestid/requestid.go`
- Create: `internal/requestid/http.go`
- Create: `internal/requestid/requestid_test.go`
- Modify: `docs/architecture/events.md`

**Steps:**
1. Define canonical header `X-Request-ID`.
2. Implement `New()` using UUID/ULID or crypto-random hex; tests must assert non-empty and safe character set, not exact values.
3. Implement `WithContext(ctx, id)`, `FromContext(ctx)`, and `SlogAttr(ctx)`.
4. Implement HTTP middleware that:
   - Accepts an inbound valid `X-Request-ID`.
   - Generates one if missing/invalid.
   - Stores it in request context.
   - Writes it to response header.
5. Reject or replace IDs containing control chars, whitespace, or length over 128.
6. Update `docs/architecture/events.md` to state NATS events include originating `request_id` in `trace` when available.
7. Add tests for inbound preservation, generated fallback, invalid replacement, and response header.

**Verification:**
```bash
go test ./internal/requestid
```
Expected: request ID tests pass.

**Commit:**
```bash
git add internal/requestid/ docs/architecture/events.md
git commit -m "feat: add request id propagation primitives"
```

---

## Task 7: Add API Server Skeleton with Health and Readiness

**Objective:** Create `tallow-api` with chi routing, structured slog request logs, config loading, typed errors, and health/readiness endpoints.

**Issues:** #3, #39, #40.

**Files:**
- Create: `cmd/tallow-api/main.go`
- Create: `internal/api/server.go`
- Create: `internal/api/routes.go`
- Create: `internal/api/health.go`
- Create: `internal/api/errors.go`
- Create: `internal/api/middleware.go`
- Create: `internal/api/health_test.go`
- Create: `internal/api/middleware_test.go`
- Create: `docs/api/openapi.yaml`

**Steps:**
1. Add dependencies: `github.com/go-chi/chi/v5`.
2. Implement `api.Server` with injected `config.Config`, `slog.Logger`, and readiness check functions.
3. Add routes:
   - `GET /healthz`: always returns `200` with `{"status":"ok"}`.
   - `GET /readyz`: returns `200` when readiness checks pass, otherwise `503` with typed error envelope.
4. Add request ID middleware from Task 6.
5. Add structured logging middleware recording request ID, method, path, status, latency, and safe error code if present.
6. Add panic recovery returning `internal_error` without stack traces in the response.
7. Add `cmd/tallow-api/main.go` loading config from environment and starting HTTP server.
8. Create `docs/api/openapi.yaml` with `/healthz` and `/readyz` paths and error envelope schema.
9. Add handler tests for health, ready success, ready failure, request ID header, and no sensitive error details.

**Verification:**
```bash
go test ./internal/api
go run ./cmd/tallow-api
curl -fsS http://127.0.0.1:8844/healthz
```
Expected: tests pass; health endpoint returns `{"status":"ok"}`. Stop the server after verification.

**Commit:**
```bash
git add cmd/tallow-api/ internal/api/ docs/api/openapi.yaml go.mod go.sum
git commit -m "feat: add api skeleton and health endpoints"
```

---

## Task 8: Add Prometheus Metrics Endpoint and Operational Diagnostics

**Objective:** Expose `/metrics` with safe `tallow_` metrics and document operational diagnostics.

**Issues:** #8, supports #3, #5, #70.

**Files:**
- Create: `internal/metrics/metrics.go`
- Create: `internal/metrics/http.go`
- Create: `internal/metrics/metrics_test.go`
- Create: `docs/operations/metrics.md`
- Modify: `internal/api/routes.go`
- Modify: `docs/api/openapi.yaml`

**Steps:**
1. Add dependency: `github.com/prometheus/client_golang/prometheus` and `prometheus/promhttp`.
2. Create a custom registry per server/test to avoid global registration collisions.
3. Register safe metrics with `tallow_` prefix:
   - `tallow_http_requests_total{method,path,status}`.
   - `tallow_http_request_duration_seconds{method,path,status}`.
   - `tallow_readiness_check_total{check,status}`.
   - placeholders for event/scheduler metrics without emitting payload labels.
4. Add `/metrics` route only when metrics are enabled.
5. Ensure labels never include package names, artifact paths, snippets, registry URLs with credentials, or raw error messages.
6. Add tests verifying `/metrics` includes `tallow_` metrics and does not include request bodies or query strings.
7. Document each metric in `docs/operations/metrics.md`.
8. Update OpenAPI with `/metrics` response.

**Verification:**
```bash
go test ./internal/metrics ./internal/api
```
Expected: metrics and API tests pass.

**Commit:**
```bash
git add internal/metrics/ internal/api/ docs/operations/metrics.md docs/api/openapi.yaml go.mod go.sum
git commit -m "feat: expose prometheus metrics"
```

---

## Task 9: Add PostgreSQL Migrations and sqlc Configuration

**Objective:** Define the initial durable schema and typed query generation for core records.

**Issues:** #4, supports #31, #32, #36, #37, #38, #70.

**Files:**
- Create: `db/migrations/000001_foundation.up.sql`
- Create: `db/migrations/000001_foundation.down.sql`
- Create: `db/queries/packages.sql`
- Create: `db/queries/artifacts.sql`
- Create: `db/queries/events.sql`
- Create: `db/queries/scheduler.sql`
- Create: `sqlc.yaml`
- Create: `internal/db/doc.go`
- Generated: `internal/db/sqlc/*.go`
- Create: `docs/architecture/storage.md`

**Steps:**
1. Add dependencies: `github.com/jackc/pgx/v5`, `github.com/golang-migrate/migrate/v4`, and database drivers.
2. Create PostgreSQL enum types for ecosystem, artifact type, acquisition status, finding severity/confidence, event publish status, scheduler job status where useful.
3. Create tables:
   - `packages`
   - `package_versions`
   - `artifacts`
   - `artifact_observations`
   - `findings`
   - `evidence_refs`
   - `users` minimal placeholder for future auth ownership.
   - `events_outbox`
   - `events_inbox` for consumer idempotency.
   - `scheduled_jobs`
4. Add uniqueness constraints matching `docs/development/testing-strategy.md` natural keys:
   - package: `ecosystem + registry_url + canonical_name`.
   - version: `package_id + normalized_version`.
   - pre-download artifact: `version_id + artifact_type + filename + download_url` where `sha256 IS NULL`.
   - immutable artifact: `version_id + artifact_type + filename + sha256` where `sha256 IS NOT NULL`.
   - finding stable ID unique.
   - outbox event ID unique.
5. Add scheduler lease columns: `kind`, `target`, `cadence_seconds`, `next_run_at`, `lease_owner`, `lease_until`.
6. Write sqlc queries for upserting packages/versions/artifacts, recording observations, inserting outbox events, claiming/releasing scheduler jobs.
7. Configure `sqlc.yaml` to generate pgx/v5 Go code under `internal/db/sqlc`.
8. Document major tables in `docs/architecture/storage.md`.
9. Run `sqlc generate`.

**Verification:**
```bash
sqlc generate
go test ./internal/db/...
```
Expected: sqlc generation succeeds; db package compiles.

**Commit:**
```bash
git add db/ sqlc.yaml internal/db/ docs/architecture/storage.md go.mod go.sum
git commit -m "feat: add foundation database schema"
```

---

## Task 10: Add Migration Runner and Database Integration Tests

**Objective:** Provide reusable migration execution for API/CLI and prove migrations apply to an empty PostgreSQL database.

**Issues:** #4, #6.

**Files:**
- Create: `internal/db/migrate.go`
- Create: `internal/db/migrate_test.go`
- Create: `internal/db/integration_test.go`
- Modify: `docs/development/local-setup.md`

**Steps:**
1. Implement `db.MigrateUp(dsn string) error` using embedded migrations or filesystem path `db/migrations` for development.
2. Implement `db.MigrateDown(dsn string, steps int) error` for tests/local reset only.
3. Add build-tagged integration tests (`//go:build integration`) that use the Compose Postgres DSN from `TALLOW_TEST_POSTGRES_DSN` or default local DSN.
4. Test applying migrations to empty DB and re-running is safe/no-op.
5. Test a simple insert/query through sqlc for packages.
6. Update local setup docs with migration command.

**Verification:**
```bash
docker compose up -d postgres
TALLOW_TEST_POSTGRES_DSN='postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable' go test -tags=integration ./internal/db
docker compose down -v
```
Expected: migrations apply and integration tests pass.

**Commit:**
```bash
git add internal/db/ docs/development/local-setup.md
git commit -m "feat: add database migration runner"
```

---

## Task 11: Define Canonical Package Identity Model

**Objective:** Implement typed package identity validation and persistence boundaries.

**Issues:** #31, prerequisite for #33, #34, #35.

**Files:**
- Create: `internal/identity/package.go`
- Create: `internal/identity/package_test.go`
- Modify: `docs/architecture/package-identity.md`
- Modify: `docs/api/openapi.yaml`

**Steps:**
1. Define `Ecosystem` enum values initially supporting `npm` and `pypi`.
2. Define `PackageIdentity` fields:
   - `Ecosystem`
   - `RawName`
   - `NormalizedName`
   - `Namespace`
   - `Name`
   - `RegistryURL`
3. Implement `Validate()` returning typed `validation_failed` errors for unknown ecosystems, empty fields, invalid separators, control chars, and unsafe registry URL.
4. Do not derive IDs from untrusted text; database IDs remain generated by PostgreSQL/application.
5. Add OpenAPI examples for npm scoped package and PyPI normalized package.
6. Add tests for valid npm scoped, valid PyPI, invalid ecosystem, empty name, control chars, and unsafe registry URL.
7. Update docs if field names differ from existing `package-identity.md`; prefer `normalized_name` in code/API and state mapping to existing `canonical_name` language.

**Verification:**
```bash
go test ./internal/identity
```
Expected: package identity tests pass.

**Commit:**
```bash
git add internal/identity/ docs/architecture/package-identity.md docs/api/openapi.yaml
git commit -m "feat: define package identity model"
```

---

## Task 12: Implement Ecosystem Name Normalizers

**Objective:** Normalize npm and PyPI package names deterministically with strict rejection of unsafe input.

**Issues:** #33, supports #31, #35.

**Files:**
- Create: `internal/identity/normalize.go`
- Create: `internal/identity/normalize_test.go`
- Modify: `docs/architecture/package-identity.md`

**Steps:**
1. Implement `NormalizePackageName(ecosystem Ecosystem, raw string) (PackageIdentityParts, error)`.
2. npm rules:
   - Lowercase ASCII package and scope.
   - Preserve scoped shape `@scope/name`.
   - Namespace stores `scope` without `@`.
   - Name stores unscoped normalized name.
   - Reject empty scope/name, multiple slashes, backslash, path traversal segments, control chars, whitespace-only values, and unsupported Unicode for now.
3. PyPI rules:
   - Use PEP 503: lowercase and collapse runs of `[-_.]+` to `-`.
   - Reject slash/backslash, path traversal, control chars, empty normalized result, unsupported Unicode for now.
4. Add at least 20 table tests across accepted, equivalent, and rejected cases.
5. Ensure no silent Unicode/path separator acceptance.
6. Document examples and rejections.

**Verification:**
```bash
go test ./internal/identity -run 'Normalize|Package'
```
Expected: normalizer tests pass with at least 20 table cases.

**Commit:**
```bash
git add internal/identity/ docs/architecture/package-identity.md
git commit -m "feat: add package name normalizers"
```

---

## Task 13: Define Version Normalization Boundaries

**Objective:** Preserve raw versions while documenting and implementing minimal normalization status for npm SemVer and PyPI PEP 440 boundaries.

**Issues:** #34.

**Files:**
- Create: `internal/identity/version.go`
- Create: `internal/identity/version_test.go`
- Modify: `docs/architecture/package-identity.md`
- Modify: `db/migrations/000001_foundation.up.sql` if version status columns are missing
- Modify: `db/queries/packages.sql`

**Steps:**
1. Define `VersionIdentity` with:
   - `RawVersion`
   - `NormalizedVersion`
   - `NormalizationStatus`: `normalized`, `stored_with_warning`, `rejected`.
   - `Warnings []string` sorted deterministically.
2. For Foundation, do not attempt full ecosystem package manager resolution. Implement conservative behavior:
   - Preserve raw version always.
   - Trim surrounding ASCII whitespace only for validation, not storage.
   - Reject empty/control-char/path-separator versions.
   - For npm, accept SemVer-like prerelease/build metadata and lowercase only where SemVer permits case-insensitive identifiers if documented.
   - For PyPI, document PEP 440 boundary and normalize simple case/punctuation only if implemented safely; otherwise store valid-looking registry versions with warning.
3. Add tests for npm prerelease/build, PyPI local versions, invalid controls, and unnormalized valid registry versions stored with warning.
4. Ensure database can store `raw_version`, `normalized_version`, and optional `normalization_status`.
5. Update docs with exact supported boundary and future parser work.

**Verification:**
```bash
go test ./internal/identity -run Version
sqlc generate
```
Expected: version tests pass and sqlc remains clean.

**Commit:**
```bash
git add internal/identity/ db/ docs/architecture/package-identity.md internal/db/ sqlc.yaml
git commit -m "feat: define version normalization boundaries"
```

---

## Task 14: Define Canonical Artifact Identity Model

**Objective:** Implement artifact identity fields and mutation semantics for npm tarballs, PyPI sdists, and PyPI wheels.

**Issues:** #32, prerequisite for #37.

**Files:**
- Create: `internal/identity/artifact.go`
- Create: `internal/identity/artifact_test.go`
- Modify: `docs/architecture/artifact-identity.md`
- Modify: `docs/api/openapi.yaml`

**Steps:**
1. Define `ArtifactKind` enum values: `npm_tgz`, `pypi_sdist`, `pypi_wheel`.
2. Define `ArtifactIdentity` fields:
   - `Kind`
   - `Filename`
   - `DownloadURL`
   - `Version`
   - `Digests` map or typed digest set.
   - `RegistryURL`
   - `ObservedAt`
3. Implement validation:
   - Filename must be basename only, no slash/backslash/control chars.
   - Download URL must be absolute HTTP(S), no embedded credentials.
   - Digest algorithms limited to known set; values lowercase hex/base64 format as applicable.
   - ObservedAt required for observations.
4. Implement `PreDownloadKey()` and `ImmutableKey()` helpers for tests and docs.
5. Add tests proving PyPI wheel variants do not collide when filenames/tags differ.
6. Document same-version artifact mutation semantics: same pre-download key resolving to a new local sha256 creates a new artifact row and mutation signal.
7. Add OpenAPI examples for npm tarball, PyPI sdist, and two PyPI wheels.

**Verification:**
```bash
go test ./internal/identity -run Artifact
```
Expected: artifact identity tests pass.

**Commit:**
```bash
git add internal/identity/ docs/architecture/artifact-identity.md docs/api/openapi.yaml
git commit -m "feat: define artifact identity model"
```

---

## Task 15: Create Identity Fixture Corpus

**Objective:** Provide reusable npm and PyPI identity fixtures loaded by Go tests and documented for future adapters.

**Issues:** #35.

**Files:**
- Create: `testdata/identity/npm/cases.json`
- Create: `testdata/identity/pypi/cases.json`
- Create: `testdata/identity/README.md`
- Create: `internal/identity/fixtures_test.go`
- Modify: `docs/development/testing-strategy.md`
- Modify: `docs/architecture/package-identity.md`

**Steps:**
1. Create JSON fixture format with fields:
   - `case_id`
   - `ecosystem`
   - `raw_name`
   - `want_normalized_name`
   - `want_namespace`
   - `want_name`
   - `want_error_code`
   - `notes`
2. Include npm fixtures for scoped names, mixed case, punctuation, invalid slashes, empty scope, invalid Unicode, and typosquat-like but valid names.
3. Include PyPI fixtures for PEP 503 collapse, mixed case, punctuation, invalid slash/backslash, empty names, unsupported Unicode, and typosquat-like but valid names.
4. Write `fixtures_test.go` to load all fixtures deterministically, sort by `case_id`, and run normalizer assertions.
5. Document each case category in `testdata/identity/README.md`.
6. Update testing strategy to require fixture loading in CI.

**Verification:**
```bash
go test ./internal/identity -run Fixtures
```
Expected: fixture corpus loads and all cases pass.

**Commit:**
```bash
git add testdata/identity/ internal/identity/ docs/development/testing-strategy.md docs/architecture/package-identity.md
git commit -m "test: add identity fixture corpus"
```

---

## Task 16: Define Event Envelope JSON Schema and Validation Helper

**Objective:** Create the versioned event envelope contract before NATS producers/consumers depend on it.

**Issues:** #36, supports #5, #40, #88.

**Files:**
- Create: `schemas/events/envelope.v1.schema.json`
- Create: `schemas/testdata/events/envelope.valid.json`
- Create: `schemas/testdata/events/envelope.invalid.unknown-major.json`
- Create: `schemas/testdata/events/envelope.invalid.missing-type.json`
- Create: `internal/events/envelope.go`
- Create: `internal/events/validate.go`
- Create: `internal/events/envelope_test.go`
- Modify: `docs/architecture/events.md`
- Modify: `scripts/validate-schemas.sh`

**Steps:**
1. Define JSON Schema requiring:
   - `id`
   - `type`
   - `version`
   - `occurred_at`
   - `producer`
   - `trace_id`
   - `data`
2. Add optional `trace.request_id` or include `request_id` in a `trace` object; keep docs and schema consistent with issue #36 and #40.
3. Define subject naming rules in docs: `<domain>.<entity>.<action>.v<major>`; examples `package.version.observed.v1`, `artifact.discovered.v1`, `artifact.mutated.v1`.
4. Implement Go `Envelope[T]` or non-generic `Envelope` with deterministic JSON tags.
5. Implement `ValidateEnvelopeVersion(version string) error` rejecting unknown major versions.
6. Add golden valid and invalid fixtures.
7. Update `scripts/validate-schemas.sh` to validate fixtures using a pinned tool available in CI, e.g. `python -m jsonschema` or `go test ./internal/events` if avoiding Python dependency.
8. Add Go tests for valid fixture, invalid missing type, and unknown major version.

**Verification:**
```bash
go test ./internal/events
make schema-validate
```
Expected: event envelope tests pass and schema fixtures validate/fail as expected.

**Commit:**
```bash
git add schemas/events/ schemas/testdata/events/ internal/events/ docs/architecture/events.md scripts/validate-schemas.sh
git commit -m "feat: define event envelope schema"
```

---

## Task 17: Define Evidence Reference Schema

**Objective:** Standardize evidence references and reject unsafe paths before analyzer output persistence.

**Issues:** #38, supports #88.

**Files:**
- Create: `schemas/evidence/evidence-ref.v1.schema.json`
- Create: `schemas/testdata/evidence/evidence-ref.file.valid.json`
- Create: `schemas/testdata/evidence/evidence-ref.metadata.valid.json`
- Create: `schemas/testdata/evidence/evidence-ref.absolute-path.invalid.json`
- Create: `internal/evidence/ref.go`
- Create: `internal/evidence/ref_test.go`
- Modify: `docs/analyzers/finding-schema.md`
- Modify: `scripts/validate-schemas.sh`

**Steps:**
1. Define `EvidenceRef` fields:
   - `kind`
   - `artifact_id`
   - `snapshot_id`
   - `path`
   - `start_line`, `end_line`
   - `start_byte`, `end_byte`
   - `hash`
   - `excerpt`
   - `excerpt_redacted`
   - `description`
2. JSON Schema must reject absolute filesystem paths, backslash paths, path traversal segments, negative ranges, and missing redaction status when excerpt is present.
3. Go validator must enforce the same path/range rules.
4. Add golden fixtures for manifest file evidence, metadata evidence, and invalid absolute path.
5. Update analyzer finding docs to reference EvidenceRef and state sorting rules.
6. Update schema validation script to include evidence fixtures.

**Verification:**
```bash
go test ./internal/evidence
make schema-validate
```
Expected: evidence validator and schema fixture checks pass.

**Commit:**
```bash
git add schemas/evidence/ schemas/testdata/evidence/ internal/evidence/ docs/analyzers/finding-schema.md scripts/validate-schemas.sh
git commit -m "feat: define evidence reference schema"
```

---

## Task 18: Define Artifact Observation Event Schema

**Objective:** Define event payload for observed package versions/artifacts without embedding raw artifact bytes.

**Issues:** #37, depends on #36 and #32.

**Files:**
- Create: `schemas/events/artifact-observed.v1.schema.json`
- Create: `schemas/testdata/events/artifact-observed.npm.valid.json`
- Create: `schemas/testdata/events/artifact-observed.pypi.valid.json`
- Create: `schemas/testdata/events/artifact-observed.missing-source.invalid.json`
- Create: `internal/events/artifact_observed.go`
- Create: `internal/events/artifact_observed_test.go`
- Modify: `docs/architecture/events.md`
- Modify: `docs/architecture/artifact-identity.md`
- Modify: `scripts/validate-schemas.sh`

**Steps:**
1. Define payload fields covering:
   - Package identity.
   - Version identity.
   - Artifact identity.
   - Registry hashes.
   - Local hashes when available.
   - Storage reference when available.
   - Observation source and timestamp.
2. Ensure schema limits event size by referencing storage/evidence locations and never embedding raw artifacts or large file contents.
3. Include valid npm and PyPI fixture events.
4. Include invalid fixture missing hash/source information where the event would be ambiguous.
5. Add Go constructors/validators that sort digest maps before stable serialization where needed.
6. Update docs with the subject name and event lifecycle.

**Verification:**
```bash
go test ./internal/events -run ArtifactObserved
make schema-validate
```
Expected: artifact observation event tests and schema validation pass.

**Commit:**
```bash
git add schemas/events/artifact-observed.v1.schema.json schemas/testdata/events/ internal/events/ docs/architecture/events.md docs/architecture/artifact-identity.md scripts/validate-schemas.sh
git commit -m "feat: define artifact observation event schema"
```

---

## Task 19: Add NATS JetStream Event Bus Integration

**Objective:** Implement durable NATS JetStream publisher/consumer helpers with readiness checks and idempotency documentation.

**Issues:** #5, supports #36, #37, #40.

**Files:**
- Create: `internal/events/nats.go`
- Create: `internal/events/publisher.go`
- Create: `internal/events/consumer.go`
- Create: `internal/events/nats_test.go`
- Create: `internal/events/integration_test.go`
- Modify: `internal/api/health.go`
- Modify: `docs/architecture/events.md`
- Modify: `docs/development/testing-strategy.md`

**Steps:**
1. Add dependency: `github.com/nats-io/nats.go`.
2. Implement `events.Connect(ctx, config)` returning a connection and JetStream context.
3. Implement readiness check that verifies JetStream is enabled via account info or stream operation, not merely TCP.
4. Implement `Publisher.Publish(ctx, subject, envelope)` that:
   - Validates envelope major version.
   - Injects request ID/trace from context when absent.
   - Publishes to JetStream and waits for ack.
   - Records safe metrics.
5. Implement consumer helper with explicit durable name, manual ack, and idempotency hook based on envelope ID.
6. Add unit tests using interfaces/fakes for envelope validation and request ID propagation.
7. Add integration tests behind `integration` tag requiring local NATS from Compose.
8. Update `/readyz` to include optional NATS readiness when configured.
9. Document at-least-once delivery, durable consumers, and idempotent handler requirement.

**Verification:**
```bash
go test ./internal/events ./internal/api
docker compose up -d nats
TALLOW_TEST_NATS_URL='nats://localhost:4222' go test -tags=integration ./internal/events
docker compose down -v
```
Expected: unit and integration tests pass; readiness fails clearly when JetStream is unavailable.

**Commit:**
```bash
git add internal/events/ internal/api/ docs/architecture/events.md docs/development/testing-strategy.md go.mod go.sum
git commit -m "feat: add nats jetstream event bus"
```

---

## Task 20: Implement Outbox Persistence Helpers

**Objective:** Persist event outbox rows transactionally before publishing and support idempotent publish acknowledgements.

**Issues:** #5, #36, #37, supports #70.

**Files:**
- Modify: `db/queries/events.sql`
- Generated: `internal/db/sqlc/*.go`
- Create: `internal/events/outbox.go`
- Create: `internal/events/outbox_test.go`
- Modify: `docs/architecture/events.md`

**Steps:**
1. Add sqlc queries:
   - `CreateOutboxEvent`.
   - `ClaimPendingOutboxEvents` with `FOR UPDATE SKIP LOCKED`.
   - `MarkOutboxPublished`.
   - `MarkOutboxFailed` with retry count and next attempt.
2. Implement outbox service that serializes envelopes deterministically and writes after domain persistence succeeds.
3. Implement publisher drain loop as a library function, not a long-running daemon yet.
4. Tests must insert duplicate event IDs and assert uniqueness/idempotent behavior.
5. Document outbox pattern in `docs/architecture/events.md`.

**Verification:**
```bash
sqlc generate
go test ./internal/events ./internal/db/...
```
Expected: outbox helpers compile and tests pass.

**Commit:**
```bash
git add db/queries/events.sql internal/db/ internal/events/ docs/architecture/events.md
git commit -m "feat: add event outbox helpers"
```

---

## Task 21: Implement Scheduler Job Model and Lease Queries

**Objective:** Add horizontally safe scheduled job claiming with validation, leases, and two-worker tests.

**Issues:** #70.

**Files:**
- Create: `internal/scheduler/job.go`
- Create: `internal/scheduler/lease.go`
- Create: `internal/scheduler/job_test.go`
- Create: `internal/scheduler/lease_test.go`
- Create: `internal/scheduler/integration_test.go`
- Modify: `db/queries/scheduler.sql`
- Generated: `internal/db/sqlc/*.go`
- Modify: `docs/architecture/polling-scheduler.md`

**Steps:**
1. Define `ScheduledJob` fields matching issue #70:
   - `kind`
   - `target`
   - `cadence`
   - `next_run_at`
   - `lease_owner`
   - `lease_until`
2. Validate recurring cadence rejects values below one minute by default.
3. Add deterministic jitter helper but keep polling adapter execution out of scope.
4. Implement lease acquisition query with `FOR UPDATE SKIP LOCKED` or atomic `UPDATE ... WHERE lease_until IS NULL OR lease_until < now()`.
5. Implement release/update query that only releases when `lease_owner` matches.
6. Unit test validation and next run calculation using fixed clocks.
7. Integration test two workers attempting to claim the same due job; assert only one succeeds.
8. Run race tests for scheduler package.
9. Update scheduler docs with exact DB lease behavior.

**Verification:**
```bash
go test ./internal/scheduler
go test -race ./internal/scheduler/...
docker compose up -d postgres
TALLOW_TEST_POSTGRES_DSN='postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable' go test -tags=integration ./internal/scheduler
docker compose down -v
```
Expected: one worker claims a due job; duplicate execution is prevented.

**Commit:**
```bash
git add internal/scheduler/ db/queries/scheduler.sql internal/db/ docs/architecture/polling-scheduler.md
git commit -m "feat: add scheduler job leases"
```

---

## Task 22: Create Standalone Tallow CLI Skeleton

**Objective:** Provide first-class `tallow` CLI with documented commands, JSON output where useful, and exit codes.

**Issues:** #6, supports #4 and #3.

**Files:**
- Create: `cmd/tallow/main.go`
- Create: `internal/cli/root.go`
- Create: `internal/cli/version.go`
- Create: `internal/cli/server.go`
- Create: `internal/cli/db.go`
- Create: `internal/cli/observe.go`
- Create: `internal/cli/analyze.go`
- Create: `internal/cli/cli_test.go`
- Create: `docs/CLI.md`

**Steps:**
1. Choose a small CLI parser. Prefer standard library `flag` for minimal dependency unless subcommands become too awkward; if using Cobra, document why.
2. Implement root `tallow --help`.
3. Implement initial commands:
   - `version` with optional `--json`.
   - `server` to run the API server using shared config.
   - `db migrate` to call `internal/db.MigrateUp`.
   - `observe` placeholder that returns clear `not implemented` exit code and does not fetch packages yet.
   - `analyze` placeholder that returns clear `not implemented` exit code and does not execute package code.
4. Define exit codes in `internal/cli` constants:
   - `0` success.
   - `1` general error.
   - `2` usage error.
   - `3` config error.
   - `4` dependency unavailable.
   - `10` not implemented for safe placeholders.
5. Add JSON output support for `version` and future machine-readable errors.
6. Add tests for help, unknown command, version JSON, db migrate argument parsing, and placeholder exit codes.
7. Document all commands and exit codes in `docs/CLI.md`.

**Verification:**
```bash
go test ./internal/cli
go run ./cmd/tallow --help
go run ./cmd/tallow version --json
```
Expected: tests pass; help and version commands exit `0`.

**Commit:**
```bash
git add cmd/tallow/ internal/cli/ docs/CLI.md go.mod go.sum
git commit -m "feat: add tallow cli skeleton"
```

---

## Task 23: Wire Docker Image to API and CLI Binaries

**Objective:** Ensure the local Docker image builds both `tallow-api` and `tallow` and Compose can run the API service.

**Issues:** #2, #3, #6.

**Files:**
- Modify: `Dockerfile`
- Modify: `docker-compose.yml`
- Modify: `docs/development/local-setup.md`

**Steps:**
1. Update `Dockerfile` builder stage to run:
   - `go build -o /out/tallow-api ./cmd/tallow-api`
   - `go build -o /out/tallow ./cmd/tallow`
2. Runtime image must copy both binaries and run as non-root where possible.
3. Compose `api` service command should run `/usr/local/bin/tallow-api` or `tallow server`, whichever is the canonical runtime.
4. Add API healthcheck using `/healthz`.
5. Verify Compose still starts Postgres/NATS independently if API build is unavailable; if API is default, ensure build succeeds in CI.
6. Update docs with `docker compose up --build api`.

**Verification:**
```bash
docker compose build api
docker compose up -d postgres nats api
curl -fsS http://127.0.0.1:8844/healthz
docker compose down -v
```
Expected: image builds and API health endpoint responds.

**Commit:**
```bash
git add Dockerfile docker-compose.yml docs/development/local-setup.md
git commit -m "build: wire docker image to tallow binaries"
```

---

## Task 24: Document Initial Threat Model and Security Boundaries

**Objective:** Make hostile package intake, deployment trust boundaries, auth risks, notification risks, archive extraction risks, and LLM usage constraints explicit.

**Issues:** #7, supports #85.

**Files:**
- Create: `docs/security/threat-model.md`
- Create: `docs/security/safe-unpack.md` if missing or expand existing file
- Create: `docs/security/auth.md`
- Create: `docs/security/llm-usage.md`
- Modify: `docs/security/no-execution-policy.md`
- Modify: `docs/security/prompt-injection.md`
- Modify: `docs/SECURITY.md` if present, otherwise create it
- Modify: `README.md`

**Steps:**
1. Threat model must document:
   - Assets: dependency inventory, registry observations, artifact bytes, evidence DB, credentials, notification channels.
   - Actors: self-hosted operator, package maintainer, compromised maintainer, registry, attacker controlling package metadata, internal reviewer.
   - Trust boundaries: API, CLI, registry HTTP, artifact storage, DB, NATS, future LLM provider, notification destinations.
2. Safe unpack doc must cover traversal, symlink/hardlink escapes, devices/FIFOs, archive bombs, high file counts, long paths, nested compression, and typed `unpack_rejected` evidence.
3. Auth doc must state Foundation has no production auth yet unless implemented; document risk and future boundary.
4. LLM usage doc must state LLMs are narrative enrichment only, cannot own severity, and must consume bounded/redacted evidence bundles after prompt-injection defenses.
5. Link docs from README and any security index.
6. Mark future hardening work clearly.
7. Keep examples defensive; no exploit automation.

**Verification:**
```bash
test -f docs/security/threat-model.md
test -f docs/security/safe-unpack.md
test -f docs/security/auth.md
test -f docs/security/llm-usage.md
```
Expected: all security docs exist and are linked.

**Commit:**
```bash
git add docs/security/ docs/SECURITY.md README.md
git commit -m "docs: add foundation threat model"
```

---

## Task 25: Add Repository Self-Protection Checklist Workflow

**Objective:** Add CI/docs checks that protect the repository and document future Tallow self-scan hooks.

**Issues:** #85.

**Files:**
- Create: `.github/workflows/security.yml`
- Create: `scripts/check-security-docs.sh`
- Modify: `docs/security/release-self-protection.md`
- Modify: `.github/workflows/ci.yml`

**Steps:**
1. Add `scripts/check-security-docs.sh` verifying required security docs exist:
   - `docs/security/threat-model.md`
   - `docs/security/safe-unpack.md`
   - `docs/security/auth.md`
   - `docs/security/llm-usage.md`
   - `docs/security/release-self-protection.md`
   - `docs/security/no-execution-policy.md`
   - `docs/security/prompt-injection.md`
2. Script must also reject default Compose privileged services with a simple parse/check or documented `docker compose config` grep gate.
3. Add `.github/workflows/security.yml` running security doc checks and Compose privilege checks.
4. Update release self-protection checklist to include:
   - Future Tallow self-scan hook.
   - SBOM roadmap.
   - Checksums roadmap.
   - Signing roadmap.
   - No privileged Docker services default.
5. Reference `security.yml` badge in README if not already present.

**Verification:**
```bash
scripts/check-security-docs.sh
docker compose config | grep -i privileged && exit 1 || true
```
Expected: docs check passes and no default privileged service is found.

**Commit:**
```bash
git add .github/workflows/security.yml scripts/check-security-docs.sh docs/security/release-self-protection.md .github/workflows/ci.yml README.md
git commit -m "ci: add repository self-protection checks"
```

---

## Task 26: Complete Generated Contract Drift Checks

**Objective:** Make contract drift failures actionable and require fixture/schema changes for public contract changes.

**Issues:** #88, depends on #36 and #38.

**Files:**
- Modify: `scripts/validate-schemas.sh`
- Modify: `scripts/generate-check.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/development/testing-strategy.md`
- Create: `docs/development/contracts.md`

**Steps:**
1. Ensure `scripts/validate-schemas.sh` validates every `schemas/**/*.schema.json` against matching valid/invalid fixtures.
2. Invalid fixtures must fail validation; the script must fail if an invalid fixture unexpectedly passes.
3. Ensure `scripts/generate-check.sh` runs `sqlc generate`, `go generate ./...`, and any schema example regeneration commands added later.
4. Failure message must include:
   - The command to run locally.
   - The expected file categories to commit.
   - A reminder to add/update golden fixtures for contract changes.
5. Add `docs/development/contracts.md` documenting schema naming, fixture naming, validation commands, generated code policy, and drift triage.
6. CI must run schema validation and generate-check as separate named jobs.

**Verification:**
```bash
make schema-validate
make generate-check
```
Expected: both pass on a clean tree. Intentionally changing a generated sqlc file should make `make generate-check` fail with an actionable message; revert the intentional change before commit.

**Commit:**
```bash
git add scripts/validate-schemas.sh scripts/generate-check.sh .github/workflows/ci.yml docs/development/testing-strategy.md docs/development/contracts.md
git commit -m "ci: enforce contract drift checks"
```

---

## Task 27: Final OpenAPI and Documentation Link Pass

**Objective:** Ensure public API/docs reflect implemented Foundation contracts and no broken obvious links remain.

**Issues:** #3, #8, #31, #32, #36, #37, #38, #39, #40.

**Files:**
- Modify: `docs/api/openapi.yaml`
- Modify: `README.md`
- Modify: `docs/development/implementation-sequence.md`
- Modify: `docs/development/testing-strategy.md`
- Modify: any docs changed by earlier tasks

**Steps:**
1. Update OpenAPI components for:
   - Error envelope.
   - Package identity examples.
   - Artifact identity examples.
   - Health/readiness/metrics paths.
2. Ensure README docs list points to files that exist or clearly marks future docs as planned.
3. Ensure implementation sequence remains aligned with actual Foundation order.
4. Ensure testing strategy includes exact commands from this plan.
5. Run a simple link/path existence check for local Markdown references where practical.
6. Do not add docs claiming analyzers/UI/LLM are implemented.

**Verification:**
```bash
test -f docs/api/openapi.yaml
test -f docs/development/local-setup.md
test -f docs/development/contracts.md
test -f docs/development/error-catalog.md
make schema-validate
```
Expected: required docs exist and schema validation passes.

**Commit:**
```bash
git add README.md docs/
git commit -m "docs: align foundation contracts"
```

---

## Task 28: Run Full Foundation Verification

**Objective:** Prove the milestone is complete and ready for PR review.

**Issues:** all Foundation issues in this plan.

**Files:**
- Modify only if verification uncovers failures.

**Steps:**
1. Run formatting:
```bash
gofmt -w cmd internal
```
2. Run unit tests:
```bash
go test ./...
```
3. Run race-sensitive scheduler tests:
```bash
go test -race ./internal/scheduler/...
```
4. Run schema validation:
```bash
make schema-validate
```
5. Run generation drift check:
```bash
make generate-check
```
6. Run Compose config:
```bash
docker compose config
```
7. Run local services smoke test:
```bash
docker compose up -d postgres nats
TALLOW_TEST_POSTGRES_DSN='postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable' go test -tags=integration ./internal/db ./internal/scheduler
TALLOW_TEST_NATS_URL='nats://localhost:4222' go test -tags=integration ./internal/events
docker compose down -v
```
8. Run API/CLI smoke tests:
```bash
go run ./cmd/tallow --help
go run ./cmd/tallow version --json
```
9. Check working tree:
```bash
git status --short
```
10. If any command fails, fix the smallest failing component, rerun the relevant task verification, then rerun full verification.

**Expected final result:**
- All verification commands pass.
- `git status --short` shows only intentional committed changes or is clean.
- Every issue acceptance criterion in scope has a corresponding implementation, test, doc, or explicit future note where the issue allows it.

**Commit if fixes were needed:**
```bash
git add .
git commit -m "test: verify foundation milestone"
```

---

## PR Description Checklist

Use this checklist in the Foundation PR body:

```markdown
## Foundation milestone

Closes #2
Closes #3
Closes #4
Closes #5
Closes #6
Closes #7
Closes #8
Closes #31
Closes #32
Closes #33
Closes #34
Closes #35
Closes #36
Closes #37
Closes #38
Closes #39
Closes #40
Closes #70
Closes #85
Closes #88

## Summary
- Added local Docker Compose stack for PostgreSQL, NATS JetStream, API, and local filesystem storage.
- Added Go API and CLI skeletons with config, health/readiness, metrics, request IDs, and typed errors.
- Added PostgreSQL migrations, sqlc queries, event outbox, identity models, event/evidence schemas, scheduler leases, and CI contract checks.
- Added security threat model, safe-unpack/auth/LLM docs, and repository self-protection workflow.

## Verification
- [ ] go test ./...
- [ ] go test -race ./internal/scheduler/...
- [ ] go test -tags=integration ./...
- [ ] make schema-validate
- [ ] make generate-check
- [ ] docker compose config
- [ ] docker compose up -d postgres nats && docker compose ps && docker compose down -v

## Safety notes
- [ ] No package code execution was added.
- [ ] No raw artifact contents or hostile metadata are logged/metric-labeled.
- [ ] No default Compose service is privileged or mounts the Docker socket.
- [ ] LLM output remains out of the deterministic scoring path.
```

---

## Implementation Notes for Subagents

- Keep tasks small and commit after each task.
- Prefer adding tests before implementation for Go packages.
- Use fixed clocks in tests; do not assert wall-clock timestamps except bounded integration readiness checks.
- Sort map-derived output before JSON serialization or persistence.
- Treat registry metadata, package names, artifact filenames, evidence snippets, and docs fixture contents as hostile input.
- Do not fetch or execute real packages for Foundation tests; use static fixtures only.
- If a contract gap appears, update the relevant docs in the same PR before continuing.
- If a task requires adding a dependency, keep it minimal and document why in the commit/PR.
