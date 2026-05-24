I could not write `/home/bcorder/Github/Tallow/security-review.md` because this subagent only has read/search tools available. Findings content:

## Review
- Correct:
  - Foundation API currently exposes only `/healthz`, `/readyz`, and optional `/metrics`; no application data APIs or package execution paths were present in `internal/api/server.go:41-45`.
  - Request IDs are bounded and character-restricted before echoing/logging, reducing header/log injection risk: `internal/requestid/http.go:7-11`, `internal/requestid/requestid.go:15-24`.
  - Evidence path validation rejects absolute paths, backslashes, and `..`: `internal/evidence/ref.go:28-31`.
  - CLI `observe` and `analyze` explicitly do not fetch or execute packages in Foundation: `internal/cli/root.go:42-44`.

- Fixed:
  - None. Review was read-only.

- Blocker:
  - Public Compose database and event bus exposure with weak/default credentials. `docker-compose.yml:8` publishes Postgres on host port `5432`, while `docker-compose.yml:5-7` defaults to `tallow/tallow`. `docker-compose.yml:18` publishes NATS client and monitoring ports, and `docker-compose.yml:17` starts NATS without auth. For a “Docker Compose first” deployment, this can expose unauthenticated NATS and weak-credential Postgres beyond the app boundary. Fix by removing host port publishing or binding to `127.0.0.1`, requiring non-default secrets, and configuring NATS auth/monitoring restrictions.
  - Metrics endpoint is unauthenticated and enabled by default. `internal/config/config.go:25-26` defaults metrics to enabled, `internal/api/server.go:43-45` mounts `/metrics` without auth, and `docker-compose.yml:28,32` binds the API to `0.0.0.0:8844`. Current metrics include request paths and readiness labels (`internal/metrics/metrics.go:20,39-42`), which can leak operational metadata and become sensitive as routes grow. Fix by disabling metrics by default for exposed deployments, binding metrics to an internal listener, or requiring auth/network isolation.

- Note:
  - `plan.md` and `progress.md` were not present at the requested paths, so I reviewed the current source/config state directly.
  - `ArtifactIdentity.Validate` accepts any URL scheme with a host and no userinfo (`internal/identity/package.go:135-137`). Before artifact acquisition lands, restrict downloads to `https` by default and add explicit SSRF protections for private/link-local hosts.
  - Public schema validation is weaker than Go evidence validation: the schema only rejects absolute paths for evidence refs, while Go also rejects backslashes and `..` (`schemas/evidence/evidence-ref.v1.schema.json:1`, `internal/evidence/ref.go:28-31`). Align schemas so analyzer/worker-side validation cannot accept traversal-like paths.