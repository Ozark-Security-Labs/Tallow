#!/usr/bin/env python3
"""Validate Tallow's OpenAPI contract without network access.

The repository stores docs/api/openapi.yaml as JSON-compatible YAML so this
script can use only the Python standard library in CI.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_PATHS = {
    "/healthz",
    "/readyz",
    "/metrics",
    "/auth/providers",
    "/auth/local/login",
    "/auth/logout",
    "/auth/me",
    "/auth/github/login",
    "/auth/github/callback",
    "/admin/users",
    "/admin/users/{user_id}/roles",
    "/packages",
    "/packages/{package_id}",
    "/packages/{package_id}/versions",
    "/versions/{version_id}",
    "/artifacts/{artifact_id}",
    "/observations",
    "/analyzer-runs",
    "/analyzer-runs/{run_id}",
    "/findings",
    "/findings/{finding_id}",
    "/graph/impact-paths",
    "/alerts",
    "/alerts/{alert_id}",
    "/notification-routes",
    "/notification-deliveries",
    "/notification-templates/preview",
    "/settings",
}

REQUIRED_SCHEMAS = {
    "ErrorResponse",
    "PageInfo",
    "Role",
    "Severity",
    "Confidence",
    "FindingStatus",
    "AlertStatus",
    "Ecosystem",
    "User",
    "Session",
    "AuthProvider",
    "Package",
    "PackageVersion",
    "Artifact",
    "Observation",
    "AnalyzerRun",
    "Finding",
    "EvidenceRef",
    "ImpactPath",
    "Alert",
    "NotificationRoute",
    "NotificationDelivery",
}


def fail(message: str) -> None:
    print(f"openapi validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate_openapi.py docs/api/openapi.yaml")
    path = Path(sys.argv[1])
    spec: dict[str, Any]
    try:
        spec = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        fail(f"{path} must be JSON-compatible YAML: {exc}")
        raise AssertionError("unreachable") from exc

    if spec.get("openapi") != "3.1.0":
        fail("openapi must be 3.1.0")
    title = spec.get("info", {}).get("title")
    version = spec.get("info", {}).get("version")
    if not title or not version:
        fail("info.title and info.version are required")

    paths = set(spec.get("paths", {}))
    missing_paths = sorted(REQUIRED_PATHS - paths)
    if missing_paths:
        fail("missing required paths: " + ", ".join(missing_paths))

    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {})
    if "cookieAuth" not in schemes:
        fail("components.securitySchemes.cookieAuth is required")
    schemas = set(components.get("schemas", {}))
    missing_schemas = sorted(REQUIRED_SCHEMAS - schemas)
    if missing_schemas:
        fail("missing required schemas: " + ", ".join(missing_schemas))

    protected_mutations = [
        ("/findings/{finding_id}", "patch"),
        ("/alerts/{alert_id}", "patch"),
        ("/notification-routes", "post"),
        ("/notification-routes/{route_id}", "patch"),
        ("/notification-routes/{route_id}/test", "post"),
        ("/settings", "patch"),
    ]
    for path_name, method in protected_mutations:
        responses = spec["paths"][path_name][method].get("responses", {})
        if "403" not in responses:
            fail(f"{method.upper()} {path_name} must document 403 permission_denied")

    print(f"Validated OpenAPI {title} {version}: {len(paths)} paths, {len(schemas)} schemas")


if __name__ == "__main__":
    main()
