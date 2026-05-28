#!/usr/bin/env python3
"""Validate notification template files.

Template fixtures are JSON-compatible YAML to avoid runtime network access or
third-party parser installation in CI.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ALLOWED_CHANNELS = {"email", "teams"}
FORBIDDEN_VARIABLES = {"raw_artifact", "raw_artifact_contents", "artifact_body", "secret", "token", "webhook_url"}


def fail(path: Path, message: str) -> None:
    print(f"{path}: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_template(path: Path) -> None:
    template: dict[str, Any]
    try:
        template = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        fail(path, f"must be JSON-compatible YAML: {exc}")
        raise AssertionError("unreachable") from exc
    for key in ["id", "version", "description", "compatible_channels", "variables", "targets"]:
        if key not in template:
            fail(path, f"missing {key}")
    channels = set(template["compatible_channels"])
    if not channels or not channels <= ALLOWED_CHANNELS:
        fail(path, "invalid compatible_channels")
    variables = template["variables"]
    for name in variables:
        lowered = name.lower()
        if lowered in FORBIDDEN_VARIABLES or "raw_artifact" in lowered:
            fail(path, f"forbidden variable {name}")
    targets = template["targets"]
    if "email" in channels:
        email = targets.get("email", {})
        for key in ["subject", "text", "html"]:
            if not email.get(key):
                fail(path, f"missing email.{key}")
    if "teams" in channels and not targets.get("teams", {}).get("card_json"):
        fail(path, "missing teams.card_json")


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: validate_notification_templates.py <template-dir>", file=sys.stderr)
        raise SystemExit(1)
    root = Path(sys.argv[1])
    files = sorted([*root.rglob("*.json"), *root.rglob("*.yaml")])
    files = [path for path in files if "testdata" not in path.parts]
    if not files:
        print(f"No notification template files found under {root}")
        return
    for path in files:
        validate_template(path)
    print(f"Validated {len(files)} notification template file(s)")


if __name__ == "__main__":
    main()
