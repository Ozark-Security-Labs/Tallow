"""Finding construction helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tallow_analyzer_sdk.constants import ANALYZER_ID, ANALYZER_VERSION, FINDING_SCHEMA_VERSION
from tallow_analyzer_sdk.finding_id import build_finding_id
from tallow_analyzer_sdk.rules import RuleMetadata


@dataclass
class FindingDraft:
    rule: RuleMetadata
    subject: dict
    title: str
    summary: str
    evidence: list[dict]
    severity_hint: str | None = None
    confidence: str | None = None
    tags: list[str] | None = None


def build_finding(
    draft: FindingDraft,
    *,
    created_at: str,
) -> dict[str, Any]:
    evidence = list(draft.evidence)
    finding_id = build_finding_id(
        FINDING_SCHEMA_VERSION,
        draft.rule.rule_id,
        draft.subject,
        evidence,
    )
    tags = sorted(set(draft.tags or ()))
    return {
        "schema_version": FINDING_SCHEMA_VERSION,
        "id": finding_id,
        "rule_id": draft.rule.rule_id,
        "rule_version": draft.rule.version,
        "analyzer_id": ANALYZER_ID,
        "analyzer_version": ANALYZER_VERSION,
        "subject": draft.subject,
        "title": draft.title,
        "summary": draft.summary,
        "category": draft.rule.category,
        "severity_hint": draft.severity_hint or draft.rule.default_severity_hint,
        "confidence": draft.confidence or draft.rule.default_confidence,
        "evidence": evidence,
        "tags": tags,
        "created_at": created_at,
    }
