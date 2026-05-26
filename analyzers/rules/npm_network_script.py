"""Detect network-capable commands in npm lifecycle scripts."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from tallow_analyzer_sdk.constants import LIFECYCLE_SCRIPT_KEYS, NETWORK_COMMAND_PATTERNS
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.rules import RuleMetadata


class NpmNetworkScriptRule:
    metadata = RuleMetadata(
        rule_id="npm.lifecycle.network_command",
        version="1.0.0",
        name="npm lifecycle network command",
        description="Detect network-capable commands in npm lifecycle scripts.",
        category="network",
        ecosystems=("npm",),
        default_severity_hint="high",
        default_confidence="high",
        inputs=("snapshot", "snapshot_diff"),
        tags=("lifecycle", "network", "npm"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        if context.ecosystem != "npm":
            return []
        walker = context.walker("to")
        compiled = [re.compile(pattern, re.IGNORECASE) for pattern in NETWORK_COMMAND_PATTERNS]
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["package.json", "**/package.json"]):
            if not match.relative_path.endswith("package.json"):
                continue
            text = walker.read_text(match.relative_path)
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            scripts = payload.get("scripts") or {}
            for key in LIFECYCLE_SCRIPT_KEYS:
                value = scripts.get(key)
                if not isinstance(value, str):
                    continue
                if not any(pattern.search(value) for pattern in compiled):
                    continue
                line_no = (
                    text.count("\n", 0, text.find(f'"{key}"')) + 1
                    if f'"{key}"' in text
                    else 1
                )
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title=f"network command in npm lifecycle script: {key}",
                        summary=f"Lifecycle script {key} contains a network-capable command.",
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=line_no,
                                end_line=line_no,
                                snippet=f"\"{key}\": \"{value[:120]}\"",
                                description=(
                                    f"Network-capable command detected in lifecycle script {key}"
                                ),
                            )
                        ],
                        tags=["network", key],
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        return findings
