# API

Tallow exposes REST `/api/v1` endpoints documented by OpenAPI. Initial docs live in `docs/api/openapi.yaml`.

## Foundation API implementation

`cmd/tallow-api` serves `/healthz`, `/readyz`, and `/metrics` with chi-compatible middleware, structured slog request logs, request IDs, typed error envelopes, and config from environment defaults.
