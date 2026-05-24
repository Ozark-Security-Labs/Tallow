# Metrics

`/metrics` emits Prometheus metrics using the `tallow_` prefix: `tallow_http_requests_total`, `tallow_http_request_duration_seconds`, and `tallow_readiness_check_total`. Labels are limited to method, path, status, and check name; artifact contents, package metadata, query strings, credentials, and raw hostile payloads are never labels.
