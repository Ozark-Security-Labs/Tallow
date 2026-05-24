# Alerts and UI Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build Tallow's auth, alerts/notifications, OpenAPI, and first React triage UI milestone covering issues #23, #24, #25, #26, #27, #72, #73, #74, #75, #76, #77, and #78.

**Architecture:** Go remains the REST/API, auth, RBAC, notification, persistence, and OpenAPI source-of-truth layer. Authentication is split behind a provider abstraction: local email/password and GitHub OAuth ship now, while OIDC, Clerk, and WorkOS remain documented provider implementations for later. The React + TypeScript + Vite UI consumes generated OpenAPI types, displays evidence-bound triage screens, and never labels a package malicious unless deterministic server data explicitly says so.

**Tech Stack:** Go, PostgreSQL migrations/queries, OpenAPI 3.1, oapi-codegen or equivalent OpenAPI validation/generation, React, TypeScript, Vite, Vitest, React Testing Library, Playwright smoke tests, SMTP, Microsoft Teams incoming webhook/workflow URLs.

**Issues covered:** #23, #24, #25, #26, #27, #72, #73, #74, #75, #76, #77, #78.

---

## Non-negotiable invariants

- Tallow is defensive, self-hosted, and evidence-bound.
- Auth provider code authenticates identity only; Tallow-owned RBAC decides authorization.
- Route handlers must depend on provider/session/RBAC interfaces, not GitHub/local implementation details.
- Sessions use HttpOnly cookies, SameSite, and Secure outside local development.
- Passwords are never stored in plaintext; use Argon2id or bcrypt with explicit versioned parameters.
- OAuth state is signed, single-use where practical, and expires.
- Teams webhook URLs, SMTP passwords, OAuth secrets, session tokens, and reset tokens are never logged or rendered.
- Notification templates may include evidence links and summaries, but never raw artifact contents or secrets.
- UI copy must say “finding”, “signal”, “evidence”, “risk”, or “review needed”; avoid overclaiming “malware” or “malicious” unless the API supplies that exact deterministic classification.
- OpenAPI is the shared contract. API handlers, tests, and UI types must stay aligned with `docs/api/openapi.yaml`.

---

## Current repository baseline

Existing relevant files:

- `AGENTS.md`
- `README.md`
- `configs/tallow.example.yml`
- `docs/api/README.md`
- `docs/api/openapi.yaml` currently contains only `/healthz`.
- `docs/security/auth.md` currently defines local, GitHub, future OIDC/Clerk/WorkOS, and roles.
- `docs/operations/notifications.md` currently names email and Microsoft Teams as initial integrations.
- `docs/ui/overview.md`
- `docs/development/testing-strategy.md`
- `docs/development/implementation-sequence.md`

Directories expected to be created or extended during this milestone:

- `cmd/tallow-api/`
- `internal/api/`
- `internal/auth/`
- `internal/auth/local/`
- `internal/auth/github/`
- `internal/rbac/`
- `internal/alerts/`
- `internal/notifications/`
- `internal/notifications/templates/`
- `internal/storage/`
- `migrations/`
- `schemas/`
- `scripts/`
- `web/`
- `.github/workflows/`

---

## Milestone completion gates

Run these from repository root `/home/srvadmin/workspace/ozark-security-labs/Tallow` before considering the milestone complete:

```bash
go test ./...
python scripts/validate_openapi.py docs/api/openapi.yaml
python scripts/validate_notification_templates.py internal/notifications/templates
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web test -- --run
npm --prefix web run build
npm --prefix web run lint
docker compose config
```

Expected final result:

- All commands pass.
- `git status --short` shows only intentional changes.
- API tests cover unauthenticated, authenticated, forbidden, OAuth callback, session, and notification failure paths.
- UI tests cover loading, error, empty, and evidence rendering states for shell and triage views.
- OpenAPI validates and generated UI/API types are up to date.
- Notification golden snapshots are deterministic and redact secrets.

---

## Implementation order

1. Lock API/auth/notification contracts and OpenAPI schema first.
2. Add persistence migrations and storage interfaces.
3. Implement auth provider abstraction, sessions, local auth, GitHub OAuth, and RBAC.
4. Implement notification template schema, renderers, email channel, Teams channel, and delivery records.
5. Scaffold React + TS + Vite UI using generated API types.
6. Add triage views for findings, packages, evidence, impact, alerts, and settings.
7. Wire docs, config examples, CI gates, and final smoke tests.

---

## Task 1: Expand OpenAPI foundations (#27)

**Objective:** Replace the placeholder OpenAPI document with shared response, error, pagination, auth, and domain schemas.

**Files:**

- Modify: `docs/api/openapi.yaml`
- Modify: `docs/api/README.md`
- Create: `scripts/validate_openapi.py`
- Create: `.github/workflows/api-contract.yml`

**Implementation details:**

`docs/api/openapi.yaml` must define:

- `servers`: local `/api/v1` base URL.
- `components.securitySchemes.cookieAuth`: session cookie auth.
- `components.schemas.ErrorResponse` with required `error.code`, `error.message`, `request_id`, optional `error.details`.
- `components.schemas.PageInfo` with `limit`, `offset`, `total`, `next_offset`.
- Enums: `Role` (`admin`, `analyst`, `viewer`), `Severity` (`info`, `low`, `medium`, `high`, `critical`), `Confidence`, `FindingStatus`, `AlertStatus`, `Ecosystem`.
- Domain schemas for `User`, `Session`, `AuthProvider`, `Package`, `PackageVersion`, `Artifact`, `Observation`, `AnalyzerRun`, `Finding`, `EvidenceRef`, `ImpactPath`, `Alert`, `NotificationRoute`, and `NotificationDelivery`.
- Stable filtering style: query params `limit`, `offset`, `sort`, `ecosystem`, `package`, `severity`, `confidence`, `status`, `from`, `to`.

**Tests and commands:**

```bash
python scripts/validate_openapi.py docs/api/openapi.yaml
```

Expected: pass and print the OpenAPI title/version.

**Commit:**

```bash
git add docs/api/openapi.yaml docs/api/README.md scripts/validate_openapi.py .github/workflows/api-contract.yml
git commit -m "docs: expand OpenAPI foundation"
```

---

## Task 2: Add auth and RBAC OpenAPI endpoints (#23, #75, #76, #77, #78)

**Objective:** Specify auth/session/provider/RBAC endpoints before implementation.

**Files:**

- Modify: `docs/api/openapi.yaml`
- Modify: `docs/security/auth.md`

**Endpoints to add:**

- `GET /auth/providers`: list enabled providers and login URLs.
- `POST /auth/local/login`: local email/password login.
- `POST /auth/logout`: invalidate current session.
- `GET /auth/me`: current user, roles, provider identity, capabilities.
- `GET /auth/github/login`: redirects to GitHub with signed state.
- `GET /auth/github/callback`: exchanges callback for session.
- `GET /admin/users`: admin-only list users.
- `PATCH /admin/users/{user_id}/roles`: admin-only role update.

**Acceptance checks:**

- All protected endpoints reference `cookieAuth`.
- Mutating admin endpoints document `403` with stable error code `permission_denied`.
- OAuth errors document `invalid_oauth_state`, `oauth_exchange_failed`, and `identity_not_allowed`.

**Commands:**

```bash
python scripts/validate_openapi.py docs/api/openapi.yaml
```

---

## Task 3: Add alerts/notifications OpenAPI endpoints (#24, #72, #73, #74)

**Objective:** Specify alert, notification route, template preview, and delivery APIs.

**Files:**

- Modify: `docs/api/openapi.yaml`
- Modify: `docs/operations/notifications.md`

**Endpoints to add:**

- `GET /alerts`: filterable alert list.
- `GET /alerts/{alert_id}`: alert detail with finding and evidence references.
- `PATCH /alerts/{alert_id}`: analyst/admin acknowledge, resolve, suppress, reopen.
- `GET /notification-routes`: admin/analyst readable routes.
- `POST /notification-routes`: admin-only create route.
- `PATCH /notification-routes/{route_id}`: admin-only update route.
- `POST /notification-routes/{route_id}/test`: admin-only send test notification.
- `GET /notification-deliveries`: delivery attempt audit list.
- `POST /notification-templates/preview`: admin-only render redacted preview.

**Acceptance checks:**

- Templates expose variables, compatible channels, and redaction behavior.
- Delivery records include status, attempt count, provider, sanitized error, and timestamps.

**Commands:**

```bash
python scripts/validate_openapi.py docs/api/openapi.yaml
```

---

## Task 4: Add UI-facing core API endpoints (#25, #26, #27)

**Objective:** Specify endpoints needed by the React shell and triage views.

**Files:**

- Modify: `docs/api/openapi.yaml`
- Modify: `docs/ui/overview.md`
- Create: `docs/ui/triage-workflow.md`

**Endpoints to add:**

- `GET /healthz`
- `GET /packages`
- `GET /packages/{package_id}`
- `GET /packages/{package_id}/versions`
- `GET /versions/{version_id}`
- `GET /artifacts/{artifact_id}`
- `GET /observations`
- `GET /analyzer-runs`
- `GET /analyzer-runs/{run_id}`
- `GET /findings`
- `GET /findings/{finding_id}`
- `PATCH /findings/{finding_id}` for triage status changes.
- `GET /graph/impact-paths` for package/version/finding impact paths.
- `GET /settings` and `PATCH /settings` for admin-only configuration metadata, not raw secrets.

**Acceptance checks:**

- Finding detail schema contains `evidence_refs`, `rule_id`, `score`, `severity`, `confidence`, `status`, `summary`, `review_guidance`.
- Evidence references point to safe evidence views or stored metadata, not raw untrusted artifact bodies.
- UI docs state that severity is deterministic server output and narrative enrichment is optional.

---

## Task 5: Add database migrations for users, identities, sessions, roles, notification routes, and deliveries (#23, #24, #76, #78)

**Objective:** Persist Tallow-owned identity, authorization, session, notification route, and delivery audit records.

**Files:**

- Create: `migrations/0005_auth_notifications.up.sql`
- Create: `migrations/0005_auth_notifications.down.sql`
- Create: `internal/storage/auth_store.go`
- Create: `internal/storage/notification_store.go`
- Create: `internal/storage/auth_store_test.go`
- Create: `internal/storage/notification_store_test.go`

**Schema requirements:**

- `users`: `id`, `email`, `display_name`, `status`, `created_at`, `updated_at`.
- `user_identities`: provider, provider_subject, username, email, user_id, unique `(provider, provider_subject)`.
- `user_credentials`: local password hash, hash algorithm/version, user_id unique.
- `user_roles`: user_id, role enum/text constrained to admin/analyst/viewer.
- `sessions`: id/token hash, user_id, provider, created_at, expires_at, revoked_at, last_seen_at.
- `oauth_states`: nonce/state hash, provider, redirect_path, expires_at, consumed_at.
- `notification_routes`: name, channel, enabled, severity threshold, filters JSON, config JSON with secrets stored as references or encrypted values when available.
- `notification_deliveries`: route_id, alert_id/finding_id, channel, status, attempts, sanitized_error, provider_message_id, created_at, sent_at.

**Tests:**

- Migration applies and rolls back.
- Unique identity constraints prevent duplicate provider subjects.
- Revoked/expired sessions are not returned.
- Delivery attempts preserve sanitized error and never persist raw webhook URL/password in error fields.

**Commands:**

```bash
go test ./internal/storage -run 'TestAuthStore|TestNotificationStore' -v
```

---

## Task 6: Implement auth provider abstraction (#75)

**Objective:** Split provider-agnostic auth contracts from concrete local and GitHub providers.

**Files:**

- Create: `internal/auth/provider.go`
- Create: `internal/auth/context.go`
- Create: `internal/auth/errors.go`
- Create: `internal/auth/fake_provider_test.go`
- Create: `internal/api/auth_middleware.go`
- Create: `internal/api/auth_middleware_test.go`
- Modify: `docs/security/auth.md`

**Interface shape:**

```go
type Provider interface {
    Name() string
    LoginMethods(ctx context.Context) ([]LoginMethod, error)
}

type PasswordProvider interface {
    Provider
    AuthenticatePassword(ctx context.Context, email, password string) (*Identity, error)
}

type OAuthProvider interface {
    Provider
    BeginOAuth(ctx context.Context, redirectPath string) (*OAuthStart, error)
    CompleteOAuth(ctx context.Context, query url.Values) (*Identity, error)
}
```

**Rules:**

- API handlers receive `auth.Manager`, not concrete provider structs.
- Provider errors map to stable API error codes.
- Fake provider tests cover success, unauthorized, disabled provider, and provider failure.

**Commands:**

```bash
go test ./internal/auth ./internal/api -run 'TestAuthProvider|TestAuthMiddleware' -v
```

---

## Task 7: Implement session manager and local auth provider (#76)

**Objective:** Support bootstrap admin/dev config, local login, secure cookies, logout, and session lookup.

**Files:**

- Create: `internal/auth/session.go`
- Create: `internal/auth/session_test.go`
- Create: `internal/auth/local/provider.go`
- Create: `internal/auth/local/password.go`
- Create: `internal/auth/local/provider_test.go`
- Create: `internal/api/auth_handlers.go`
- Create: `internal/api/auth_handlers_test.go`
- Modify: `configs/tallow.example.yml`
- Modify: `docs/security/auth.md`
- Modify: `docs/deployment/configuration.md`

**Implementation requirements:**

- Local provider supports configured bootstrap admin only until the first persisted admin exists.
- Persisted local users authenticate by email and password hash.
- Password hash uses Argon2id or bcrypt with tests for verify-success and verify-failure.
- Session token is random, stored hashed, and returned only as cookie.
- Cookie name: `tallow_session`.
- Cookie flags: `HttpOnly=true`, `SameSite=Lax` or `Strict`; `Secure=true` unless `server.dev_insecure_cookies=true`.
- Logout revokes the server-side session and expires the cookie.

**Commands:**

```bash
go test ./internal/auth ./internal/auth/local ./internal/api -run 'TestSession|TestLocal|TestLogin|TestLogout' -v
```

---

## Task 8: Implement GitHub OAuth provider (#77)

**Objective:** Add built-in GitHub OAuth without requiring Clerk, WorkOS, or another hosted auth service.

**Files:**

- Create: `internal/auth/github/provider.go`
- Create: `internal/auth/github/client.go`
- Create: `internal/auth/github/state.go`
- Create: `internal/auth/github/provider_test.go`
- Create: `internal/auth/github/testdata/user.json`
- Modify: `internal/api/auth_handlers.go`
- Modify: `internal/api/auth_handlers_test.go`
- Modify: `configs/tallow.example.yml`
- Modify: `docs/security/auth.md`

**Implementation requirements:**

- Config supports `auth.github.client_id`, `client_secret`, `callback_url`, `allowed_orgs`, `allowed_teams`.
- OAuth state includes provider, nonce, issued_at, expires_at, redirect_path and is HMAC-signed.
- Callback validates signature and expiry before token exchange.
- GitHub HTTP client is interface-backed for tests.
- Tests mock token exchange, `/user`, `/user/emails`, and allowed org/team checks.
- Webhook/client secrets and access tokens are never logged.

**Commands:**

```bash
go test ./internal/auth/github ./internal/api -run 'TestGitHubOAuth|TestOAuthCallback' -v
```

---

## Task 9: Implement RBAC helper and route matrix (#78)

**Objective:** Enforce admin/analyst/viewer permissions consistently across API routes and UI capability responses.

**Files:**

- Create: `internal/rbac/rbac.go`
- Create: `internal/rbac/matrix.go`
- Create: `internal/rbac/rbac_test.go`
- Modify: `internal/api/auth_middleware.go`
- Modify: `internal/api/*_handlers.go` as routes are implemented
- Modify: `docs/security/auth.md`

**Role matrix:**

- `viewer`: read dashboard, packages, versions, artifacts metadata, findings, alerts, impact paths, analyzer runs, non-secret settings metadata.
- `analyst`: viewer permissions plus triage findings/alerts, acknowledge/resolve/reopen alerts, create comments/notes if comments exist.
- `admin`: analyst permissions plus manage users/roles, notification routes, auth providers, integrations, settings, and test notifications.

**Tests:**

- Viewer cannot mutate scans, findings, alerts, settings, users, notification routes, or integrations.
- Analyst can mutate triage state but not integrations/users/settings.
- Admin can access admin endpoints.
- Denials return HTTP 403 with `permission_denied`.

**Commands:**

```bash
go test ./internal/rbac ./internal/api -run 'TestRBAC|TestPermissionDenied' -v
```

---

## Task 10: Define notification template schema (#72)

**Objective:** Create deterministic schema and validation for notification templates and variables.

**Files:**

- Create: `schemas/notification-template.schema.json`
- Create: `internal/notifications/templates/schema.go`
- Create: `internal/notifications/templates/validate.go`
- Create: `internal/notifications/templates/validate_test.go`
- Create: `scripts/validate_notification_templates.py`
- Modify: `docs/operations/notifications.md`

**Template schema requirements:**

- Template metadata: `id`, `version`, `description`, `compatible_channels`.
- Declared variables with type, required/optional, redaction policy, and description.
- Channel render targets: `email.subject`, `email.text`, `email.html`, `teams.card_json`.
- Validation fails for undeclared variables, disallowed functions, raw artifact content variables, and missing required channel bodies.
- Rendering sorts maps/lists deterministically where order is not semantic.

**Commands:**

```bash
go test ./internal/notifications/templates -run 'TestTemplateValidation' -v
python scripts/validate_notification_templates.py internal/notifications/templates
```

---

## Task 11: Implement email notification templates (#73)

**Objective:** Add high-risk finding, scan failed, and digest templates with plaintext and HTML rendering.

**Files:**

- Create: `internal/notifications/templates/email/high_risk_finding.yaml`
- Create: `internal/notifications/templates/email/scan_failed.yaml`
- Create: `internal/notifications/templates/email/digest.yaml`
- Create: `internal/notifications/templates/email/testdata/*.golden.txt`
- Create: `internal/notifications/templates/email/testdata/*.golden.html`
- Create: `internal/notifications/templates/email/templates_test.go`
- Modify: `docs/operations/notifications.md`

**Requirements:**

- Include package, version, ecosystem, severity, confidence, rule IDs, concise evidence summary, triage URL, and recommended reviewer action.
- Redact secrets and full sensitive URLs where configured.
- Use wording like “Tallow found signals requiring review”, not “Tallow confirmed malware”.
- Snapshot tests must be stable.

**Commands:**

```bash
go test ./internal/notifications/templates/... -run 'TestEmailTemplates' -v
```

---

## Task 12: Implement Microsoft Teams templates (#74)

**Objective:** Add Teams card JSON templates and validation for Teams delivery.

**Files:**

- Create: `internal/notifications/templates/teams/high_risk_finding.yaml`
- Create: `internal/notifications/templates/teams/scan_failed.yaml`
- Create: `internal/notifications/templates/teams/digest.yaml`
- Create: `internal/notifications/templates/teams/testdata/*.golden.json`
- Create: `internal/notifications/templates/teams/templates_test.go`
- Modify: `docs/operations/notifications.md`

**Requirements:**

- Render valid Teams card JSON.
- Include package/version/severity/rule IDs/evidence link.
- Do not include webhook URL, OAuth token, raw artifact body, or untrusted markdown that can spoof actions.
- Snapshot tests compare canonical JSON.

**Commands:**

```bash
go test ./internal/notifications/templates/... -run 'TestTeamsTemplates' -v
```

---

## Task 13: Implement notification channels and delivery recording (#24)

**Objective:** Send rendered notifications through SMTP and Teams, record attempts, and handle failures safely.

**Files:**

- Create: `internal/notifications/channel.go`
- Create: `internal/notifications/email.go`
- Create: `internal/notifications/teams.go`
- Create: `internal/notifications/dispatcher.go`
- Create: `internal/notifications/redact.go`
- Create: `internal/notifications/*_test.go`
- Create: `internal/api/notification_handlers.go`
- Create: `internal/api/notification_handlers_test.go`
- Modify: `configs/tallow.example.yml`
- Modify: `docs/operations/notifications.md`

**Requirements:**

- SMTP config supports host, port, username, password secret reference, from, to, TLS mode.
- Teams config supports webhook/workflow URL secret reference.
- Dispatcher records pending/sent/failed delivery attempts.
- Failures store sanitized error messages only.
- Test notification endpoint sends a synthetic evidence-bound preview.

**Commands:**

```bash
go test ./internal/notifications ./internal/api -run 'TestNotification|TestEmail|TestTeams|TestDelivery' -v
```

---

## Task 14: Implement core REST handlers for UI data (#25, #26, #27)

**Objective:** Add handler scaffolding and tests for packages, versions, findings, alerts, analyzer runs, graph, and settings.

**Files:**

- Create: `internal/api/router.go`
- Create: `internal/api/errors.go`
- Create: `internal/api/pagination.go`
- Create: `internal/api/packages_handlers.go`
- Create: `internal/api/findings_handlers.go`
- Create: `internal/api/alerts_handlers.go`
- Create: `internal/api/graph_handlers.go`
- Create: `internal/api/settings_handlers.go`
- Create: `internal/api/*_test.go`
- Modify: `cmd/tallow-api/main.go`

**Requirements:**

- Response shapes match `docs/api/openapi.yaml`.
- Filtering, pagination, and sorting are stable and validated.
- All protected endpoints require session auth.
- Mutating endpoints enforce RBAC.
- Handler tests use fake stores and fake auth.

**Commands:**

```bash
go test ./internal/api -v
```

---

## Task 15: Generate API types/client for UI (#25, #27)

**Objective:** Make the web app consume OpenAPI-derived types instead of hand-written response shapes.

**Files:**

- Create: `web/package.json`
- Create: `web/tsconfig.json`
- Create: `web/vite.config.ts`
- Create: `web/src/api/generated.ts`
- Create: `web/src/api/client.ts`
- Create: `web/src/api/client.test.ts`
- Modify: `docs/api/README.md`

**Requirements:**

- Add script `npm --prefix web run generate:api` that regenerates `web/src/api/generated.ts` from `docs/api/openapi.yaml`.
- API client sends credentials for cookie auth.
- API client normalizes `ErrorResponse` for UI display.
- Tests mock fetch for success, validation error, auth error, and server error.

**Commands:**

```bash
npm --prefix web ci
npm --prefix web run generate:api
npm --prefix web test -- --run src/api/client.test.ts
```

---

## Task 16: Scaffold React + TypeScript + Vite UI shell (#25)

**Objective:** Create the first runnable UI shell with auth state, navigation, layout, loading/error/empty states, and route placeholders.

**Files:**

- Create: `web/index.html`
- Create: `web/src/main.tsx`
- Create: `web/src/App.tsx`
- Create: `web/src/routes.tsx`
- Create: `web/src/auth/AuthContext.tsx`
- Create: `web/src/components/Layout.tsx`
- Create: `web/src/components/LoadingState.tsx`
- Create: `web/src/components/ErrorState.tsx`
- Create: `web/src/components/EmptyState.tsx`
- Create: `web/src/styles.css`
- Create: `web/src/routes/Dashboard.tsx`
- Create: `web/src/routes/Packages.tsx`
- Create: `web/src/routes/Findings.tsx`
- Create: `web/src/routes/Impact.tsx`
- Create: `web/src/routes/AnalyzerRuns.tsx`
- Create: `web/src/routes/Settings.tsx`
- Create: `web/src/App.test.tsx`
- Modify: `docs/ui/overview.md`

**Navigation routes:**

- `/` dashboard
- `/packages`
- `/packages/:packageId`
- `/findings`
- `/findings/:findingId`
- `/alerts/:alertId`
- `/impact`
- `/analyzer-runs`
- `/settings`

**Commands:**

```bash
npm --prefix web run typecheck
npm --prefix web test -- --run src/App.test.tsx
npm --prefix web run build
```

---

## Task 17: Add login/logout and auth-aware UI (#25, #76, #77, #78)

**Objective:** Support local login, GitHub login link, logout, current user display, and capability-driven navigation.

**Files:**

- Create: `web/src/routes/Login.tsx`
- Create: `web/src/auth/useRequireAuth.ts`
- Create: `web/src/auth/capabilities.ts`
- Create: `web/src/auth/AuthContext.test.tsx`
- Modify: `web/src/routes.tsx`
- Modify: `web/src/components/Layout.tsx`

**Requirements:**

- `GET /auth/providers` drives which login buttons appear.
- Local login posts to `/auth/local/login`.
- GitHub button navigates to `/auth/github/login`.
- Logout posts `/auth/logout`, clears UI state, and redirects to login.
- Admin-only nav items hide for analyst/viewer but server RBAC remains authoritative.

**Commands:**

```bash
npm --prefix web test -- --run 'src/auth/**/*.test.tsx' 'src/routes/Login.test.tsx'
npm --prefix web run typecheck
```

---

## Task 18: Build findings list and filters (#26)

**Objective:** Implement evidence-bound findings list with ecosystem/package/severity/confidence/status filters.

**Files:**

- Create: `web/src/routes/findings/FindingsList.tsx`
- Create: `web/src/routes/findings/FindingsFilters.tsx`
- Create: `web/src/routes/findings/SeverityBadge.tsx`
- Create: `web/src/routes/findings/FindingStatusBadge.tsx`
- Create: `web/src/routes/findings/FindingsList.test.tsx`
- Modify: `web/src/routes/Findings.tsx`
- Modify: `docs/ui/triage-workflow.md`

**Requirements:**

- Filters map directly to OpenAPI query params.
- Loading/error/empty states are visible and tested.
- Rows show package, version, severity, confidence, status, rule IDs, evidence count, updated time.
- Copy says “signals” or “findings”, not unsupported maliciousness claims.

**Commands:**

```bash
npm --prefix web test -- --run src/routes/findings/FindingsList.test.tsx
npm --prefix web run typecheck
```

---

## Task 19: Build finding detail and evidence view (#26)

**Objective:** Show finding detail, evidence references, triage status actions, and safe reviewer guidance.

**Files:**

- Create: `web/src/routes/findings/FindingDetail.tsx`
- Create: `web/src/routes/findings/EvidencePanel.tsx`
- Create: `web/src/routes/findings/TriageActions.tsx`
- Create: `web/src/routes/findings/FindingDetail.test.tsx`
- Modify: `web/src/routes.tsx`
- Modify: `docs/ui/triage-workflow.md`

**Requirements:**

- Evidence panel shows evidence type, path/ref, hash/range/line metadata, excerpt if safe, and source analyzer.
- Raw artifact content is not rendered unless API explicitly marks excerpt safe.
- Triage actions are enabled for analyst/admin only.
- Viewer sees read-only status.
- Tests cover safe excerpt rendering and unsafe excerpt suppression.

**Commands:**

```bash
npm --prefix web test -- --run src/routes/findings/FindingDetail.test.tsx
npm --prefix web run typecheck
```

---

## Task 20: Build package/version/artifact detail views (#26)

**Objective:** Show package and version observations, artifacts, analyzer runs, and related findings.

**Files:**

- Create: `web/src/routes/packages/PackageList.tsx`
- Create: `web/src/routes/packages/PackageDetail.tsx`
- Create: `web/src/routes/packages/VersionDetail.tsx`
- Create: `web/src/routes/packages/ArtifactSummary.tsx`
- Create: `web/src/routes/packages/PackageDetail.test.tsx`
- Modify: `web/src/routes/Packages.tsx`
- Modify: `docs/ui/triage-workflow.md`

**Requirements:**

- Package detail links versions, observations, artifacts, analyzer runs, findings, and alerts.
- Artifact display emphasizes metadata, hashes, size, and source registry; no execution or raw content.
- Empty state explains that graph/observation data may not exist yet.

**Commands:**

```bash
npm --prefix web test -- --run src/routes/packages/PackageDetail.test.tsx
npm --prefix web run typecheck
```

---

## Task 21: Build impact path and alert detail views (#26)

**Objective:** Show impacted sources/dependencies where graph data exists and alert status details.

**Files:**

- Create: `web/src/routes/impact/ImpactPaths.tsx`
- Create: `web/src/routes/impact/ImpactPaths.test.tsx`
- Create: `web/src/routes/alerts/AlertDetail.tsx`
- Create: `web/src/routes/alerts/AlertDetail.test.tsx`
- Modify: `web/src/routes.tsx`
- Modify: `docs/ui/triage-workflow.md`

**Requirements:**

- Impact view accepts package/version/finding filters.
- Alert detail shows severity, status, affected package/version, related findings, notification deliveries, and evidence links.
- Triage actions follow RBAC capabilities.
- Copy avoids unsupported claims.

**Commands:**

```bash
npm --prefix web test -- --run 'src/routes/impact/*.test.tsx' 'src/routes/alerts/*.test.tsx'
npm --prefix web run typecheck
```

---

## Task 22: Build settings and notification route UI (#25, #24, #78)

**Objective:** Add settings screens for auth metadata and notification route management with admin-only controls.

**Files:**

- Create: `web/src/routes/settings/SettingsHome.tsx`
- Create: `web/src/routes/settings/AuthSettings.tsx`
- Create: `web/src/routes/settings/NotificationRoutes.tsx`
- Create: `web/src/routes/settings/NotificationRouteForm.tsx`
- Create: `web/src/routes/settings/NotificationRoutes.test.tsx`
- Modify: `web/src/routes/Settings.tsx`
- Modify: `docs/ui/overview.md`

**Requirements:**

- Viewer/analyst see read-only non-secret settings metadata where allowed.
- Admin can create/update notification routes and send test notification.
- Secret fields show configured/not configured state only; never echo values.
- Tests verify admin controls hidden for non-admin roles.

**Commands:**

```bash
npm --prefix web test -- --run src/routes/settings/NotificationRoutes.test.tsx
npm --prefix web run typecheck
```

---

## Task 23: Add UI smoke tests and accessibility gates (#25, #26)

**Objective:** Add browser smoke coverage for shell, login, findings, and package detail flows.

**Files:**

- Create: `web/playwright.config.ts`
- Create: `web/tests/smoke.spec.ts`
- Create: `web/src/test/mswServer.ts`
- Create: `web/src/test/fixtures.ts`
- Modify: `web/package.json`
- Modify: `.github/workflows/ui.yml`

**Requirements:**

- Mock API responses from OpenAPI-compatible fixtures.
- Smoke tests cover dashboard load, login redirect, findings filters, finding detail, package detail, settings RBAC visibility.
- Add basic accessibility check if project chooses `@axe-core/playwright`; otherwise document deferral.

**Commands:**

```bash
npm --prefix web run test:e2e
npm --prefix web run build
```

---

## Task 24: Wire configuration docs and examples (#23, #24, #25, #27)

**Objective:** Document runtime configuration for auth providers, sessions, RBAC, notification channels, and UI development.

**Files:**

- Modify: `configs/tallow.example.yml`
- Modify: `README.md`
- Modify: `docs/security/auth.md`
- Modify: `docs/operations/notifications.md`
- Modify: `docs/deployment/configuration.md`
- Modify: `docs/ui/overview.md`
- Modify: `docs/api/README.md`

**Required config sections:**

```yaml
auth:
  session:
    cookie_name: tallow_session
    ttl: 24h
    secure_cookies: true
  local:
    enabled: true
    bootstrap_admin_email: admin@example.com
  github:
    enabled: false
    client_id: ""
    client_secret_ref: TALLOW_GITHUB_CLIENT_SECRET
    callback_url: http://localhost:8080/api/v1/auth/github/callback
    allowed_orgs: []
    allowed_teams: []
notifications:
  email:
    enabled: false
    smtp_host: localhost
    smtp_port: 1025
    username: ""
    password_ref: TALLOW_SMTP_PASSWORD
    from: tallow@example.com
  teams:
    enabled: false
    webhook_url_ref: TALLOW_TEAMS_WEBHOOK_URL
ui:
  base_url: http://localhost:5173
```

**Commands:**

```bash
python scripts/validate_openapi.py docs/api/openapi.yaml
python scripts/validate_notification_templates.py internal/notifications/templates
```

---

## Task 25: Add final CI workflow and full milestone gate (#23-#27, #72-#78)

**Objective:** Ensure auth, notification, API, and UI checks run in CI and locally.

**Files:**

- Create: `.github/workflows/auth-alerts-ui.yml`
- Modify: `docs/development/testing-strategy.md`
- Modify: `docs/development/implementation-sequence.md`

**Workflow jobs:**

- Go tests: `go test ./...`
- OpenAPI validation: `python scripts/validate_openapi.py docs/api/openapi.yaml`
- Notification template validation: `python scripts/validate_notification_templates.py internal/notifications/templates`
- UI install/typecheck/test/build/lint.
- Optional docker compose config validation once compose files exist.

**Final command block:**

```bash
go test ./...
python scripts/validate_openapi.py docs/api/openapi.yaml
python scripts/validate_notification_templates.py internal/notifications/templates
npm --prefix web ci
npm --prefix web run generate:api
npm --prefix web run typecheck
npm --prefix web test -- --run
npm --prefix web run lint
npm --prefix web run build
npm --prefix web run test:e2e
docker compose config
git status --short
```

Expected:

- All checks pass or any unavailable infrastructure is explicitly documented in the PR with a follow-up issue.
- No generated files are stale after rerunning generation commands.
- No secrets appear in test snapshots, logs, docs examples, Teams card fixtures, or HTML email fixtures.

---

## Definition of done

- Issues #23-#27 and #72-#78 acceptance criteria are satisfied.
- `docs/api/openapi.yaml` covers health, auth, packages, versions, artifacts, observations, analyzer runs, findings, graph/impact, alerts, notification routes/deliveries, and settings.
- Auth abstraction cleanly supports local and GitHub now, with OIDC/Clerk/WorkOS extension points documented but not overbuilt.
- Roles `admin`, `analyst`, and `viewer` are enforced server-side and reflected in UI capabilities.
- Email and Microsoft Teams templates render deterministic, redacted, evidence-bound notifications.
- Delivery attempts are recorded and failures are sanitized.
- React + TS + Vite UI builds, typechecks, and provides shell, auth state, dashboard/navigation, findings/package/impact/alert/settings views.
- UI uses generated OpenAPI types and has tests for loading/error/empty states.
- Documentation explains local API/UI runs, auth configuration, GitHub OAuth setup, and notification setup.
- Final gates pass from `/home/srvadmin/workspace/ozark-security-labs/Tallow`.
