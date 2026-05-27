"""Detect npm lifecycle scripts in package.json."""

from __future__ import annotations

import json
from collections.abc import Iterable

from rules.npm_json import span_for_script_key
from tallow_analyzer_sdk.constants import LIFECYCLE_SCRIPT_KEYS
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.rules import RuleMetadata

PACKAGE_JSON = "package.json"


class NpmLifecycleRule:
    metadata = RuleMetadata(
        rule_id="npm.lifecycle.install_script",
        version="1.0.0",
        name="npm lifecycle install script",
        description="Detect npm lifecycle scripts that execute during install.",
        category="script",
        ecosystems=("npm",),
        default_severity_hint="medium",
        default_confidence="high",
        inputs=("snapshot", "snapshot_diff"),
        tags=("lifecycle", "npm"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        if context.ecosystem != "npm":
            return []
        walker = context.walker("to")
        matches = [
            item
            for item in walker.iter_files(["package.json", "**/package.json"])
            if item.relative_path.endswith("package.json")
        ]
        findings: list[FindingDraft] = []
        for match in matches[: context.max_findings_per_rule]:
            text = walker.read_text(match.relative_path)
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            scripts = payload.get("scripts") or {}
            for key in LIFECYCLE_SCRIPT_KEYS:
                value = scripts.get(key)
                if not isinstance(value, str) or not value.strip():
                    continue
                line_no, start_byte, end_byte = span_for_script_key(text, key)
                snippet = f"\"{key}\": \"{value}\""
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title=f"npm lifecycle script present: {key}",
                        summary=f"package.json defines lifecycle script key {key}.",
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=line_no,
                                end_line=line_no,
                                start_byte=start_byte,
                                end_byte=end_byte,
                                snippet=snippet,
                                description=f"Lifecycle script key {key} present in package.json",
                            )
                        ],
                        tags=["lifecycle", key],
                    )
                )
        return findings
