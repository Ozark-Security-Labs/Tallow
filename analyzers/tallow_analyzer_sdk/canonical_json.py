"""Canonical JSON serialization and deterministic sorting."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

from tallow_analyzer_sdk.constants import SEVERITY_RANK

RUNTIME_OUTPUT_FIELDS = {"created_at"}
RUNTIME_METRIC_FIELDS = set()


def canonical_dumps(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_dumps(value).encode("utf-8")).hexdigest()


def sort_findings(findings: list[dict]) -> list[dict]:
    def sort_key(finding: dict) -> tuple:
        severity = finding.get("severity_hint", "info")
        evidence = finding.get("evidence") or [{}]
        first = evidence[0] if evidence else {}
        return (
            SEVERITY_RANK.get(severity, 99),
            finding.get("rule_id", ""),
            first.get("path", ""),
            first.get("start_line", -1),
            first.get("start_byte", -1),
            finding.get("id", ""),
        )

    return sorted(findings, key=sort_key)


def strip_runtime_fields(payload: dict) -> dict:
    cleaned = deepcopy(payload)
    for finding in cleaned.get("findings", []):
        for field in RUNTIME_OUTPUT_FIELDS:
            finding.pop(field, None)
    metrics = cleaned.get("metrics")
    if isinstance(metrics, dict):
        for field in RUNTIME_METRIC_FIELDS:
            metrics.pop(field, None)
    return cleaned
