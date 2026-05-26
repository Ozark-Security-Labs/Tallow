"""Detect webhook and exfiltration URLs in executable package paths."""

from __future__ import annotations

import re
from collections.abc import Iterable

from tallow_analyzer_sdk.constants import WEBHOOK_URL_PATTERNS
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.paths import is_doc_path
from tallow_analyzer_sdk.redaction import redact_url
from tallow_analyzer_sdk.rules import RuleMetadata

URL_PATTERN = re.compile(r"https?://[^\s'\")<>]+", re.I)


class WebhookUrlRule:
    metadata = RuleMetadata(
        rule_id="network.webhook_url",
        version="1.0.0",
        name="webhook url",
        description="Detect webhook and exfiltration-oriented URLs in executable package paths.",
        category="network",
        ecosystems=("npm", "pypi", "*"),
        default_severity_hint="high",
        default_confidence="medium",
        inputs=("snapshot", "snapshot_diff"),
        tags=("network", "webhook"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        walker = context.walker("to")
        patterns = [re.compile(pattern, re.I) for pattern in WEBHOOK_URL_PATTERNS]
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["**/*"]):
            if is_doc_path(match.relative_path):
                continue
            text = walker.read_text(match.relative_path)
            for line_no, line in enumerate(text.splitlines(), start=1):
                url = _matching_url(line, patterns)
                if not url:
                    continue
                confidence = (
                    "medium"
                    if match.relative_path.endswith((".js", ".ts", ".py", ".sh", ".json"))
                    else "low"
                )
                if confidence == "low":
                    continue
                snippet = redact_url(url)
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="webhook or exfiltration URL detected",
                        summary=f"Webhook-like URL detected in {match.relative_path}.",
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=line_no,
                                end_line=line_no,
                                snippet=snippet,
                                description="Webhook or exfiltration URL pattern detected",
                            )
                        ],
                        confidence=confidence,
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        return findings


def _matching_url(line: str, patterns: list[re.Pattern[str]]) -> str | None:
    for url_match in URL_PATTERN.finditer(line):
        url = url_match.group(0)
        if any(pattern.search(url) for pattern in patterns):
            return url
    return None
