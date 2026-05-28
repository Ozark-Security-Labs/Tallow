# API

Tallow exposes REST endpoints documented by `docs/api/openapi.yaml`.

## Contract

The OpenAPI document is the shared contract for handlers, tests, and the React UI client. It defines:

- health/readiness/metrics;
- auth providers, local login/logout, GitHub OAuth, current-user, and admin user/role endpoints;
- packages, versions, artifacts, observations, analyzer runs, findings, graph impact paths, source correlations, alerts, notification routes/deliveries, and settings;
- the stable error envelope `error.code`, `error.message`, `error.request_id`, and optional `error.details`;
- common pagination parameters `limit`, `offset`, `sort`, and `PageInfo` responses where list endpoints need total counts;
- cookie auth through the `tallow_session` HttpOnly session cookie.

The API server currently mounts implementation routes under `/v1/...`; deployments may expose these through `/api/v1` as shown by the OpenAPI server URL.

## Validation

Run:

```sh
python scripts/validate_openapi.py docs/api/openapi.yaml
```

The validator is intentionally standard-library only and checks the milestone-required path, schema, security, and permission-denied contracts.
