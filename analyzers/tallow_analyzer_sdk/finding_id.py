"""Deterministic finding ID builder."""

from __future__ import annotations

from typing import Any

from tallow_analyzer_sdk.canonical_json import canonical_sha256

FINDING_ID_PREFIX = "fin_v1_"


def normalize_subject_for_id(subject: dict) -> dict:
    keys = (
        "ecosystem",
        "package_name",
        "version",
        "to_version",
        "artifact_id",
        "snapshot_id",
        "from_artifact_id",
        "to_artifact_id",
    )
    normalized: dict[str, Any] = {}
    for key in keys:
        value = subject.get(key)
        if value not in (None, ""):
            normalized[key] = value
    if "version" not in normalized and subject.get("to_version"):
        normalized["to_version"] = subject["to_version"]
    return normalized


def _evidence_value_hash(item: dict) -> str | None:
    if "value_hash" in item:
        return str(item["value_hash"])
    value = item.get("value")
    if value is None:
        hash_value = item.get("hash")
        return str(hash_value) if hash_value else None
    text = str(value)
    if len(text) <= 64 and not any(ch in text for ch in ("@", "://")):
        return text
    from tallow_analyzer_sdk.redaction import hash_sensitive_value

    return hash_sensitive_value(text)


def normalize_evidence_for_id(evidence: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in evidence:
        entry = {
            "kind": item.get("kind"),
            "artifact_id": item.get("artifact_id"),
            "snapshot_id": item.get("snapshot_id"),
            "path": item.get("path"),
            "start_line": item.get("start_line"),
            "end_line": item.get("end_line"),
            "start_byte": item.get("start_byte"),
            "end_byte": item.get("end_byte"),
        }
        value_hash = _evidence_value_hash(item)
        if value_hash is not None:
            entry["value_hash"] = value_hash
        normalized.append({k: v for k, v in entry.items() if v is not None})

    return sorted(
        normalized,
        key=lambda item: (
            item.get("kind", ""),
            item.get("path", ""),
            item.get("start_line", -1),
            item.get("end_line", -1),
            item.get("start_byte", -1),
            item.get("end_byte", -1),
            item.get("value_hash", ""),
        ),
    )


def build_finding_id(schema_version: str, rule_id: str, subject: dict, evidence: list[dict]) -> str:
    payload = {
        "schema_version": schema_version,
        "rule_id": rule_id,
        "subject": normalize_subject_for_id(subject),
        "evidence": normalize_evidence_for_id(evidence),
    }
    digest = canonical_sha256(payload)[:32]
    return f"{FINDING_ID_PREFIX}{digest}"
