"""Detect unexpected native binary artifacts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from tallow_analyzer_sdk.constants import BINARY_MAGICS
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import binary_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.rules import RuleMetadata


class UnexpectedBinaryRule:
    metadata = RuleMetadata(
        rule_id="artifact.binary.unexpected",
        version="1.0.0",
        name="unexpected binary artifact",
        description="Detect newly added native binaries unless explicitly allowed.",
        category="binary",
        ecosystems=("npm", "pypi", "*"),
        default_severity_hint="medium",
        default_confidence="high",
        inputs=("snapshot", "snapshot_diff"),
        tags=("binary", "artifact"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        is_diff = "from" in context.snapshot_roots
        if not is_diff and context.package_binary_allowed:
            return []
        walker = context.walker("to")
        previous_paths = _previous_paths(context)
        findings: list[FindingDraft] = []
        for match in walker.iter_files(include_binary=True):
            if is_diff and match.relative_path in previous_paths:
                continue
            if match.relative_path in context.allowed_binary_paths:
                continue
            data = walker.read_bytes(match.relative_path, max_bytes=16)
            magic = _detect_magic(data)
            if magic is None:
                continue
            digest = hashlib.sha256(walker.read_bytes(match.relative_path)).hexdigest()
            findings.append(
                FindingDraft(
                    rule=self.metadata,
                    subject=context.subject,
                    title="unexpected binary artifact detected",
                    summary=(
                        f"Binary artifact with {magic} magic bytes detected at "
                        f"{match.relative_path}."
                    ),
                    evidence=[
                        binary_evidence(
                            match.relative_path,
                            magic,
                            match.size_bytes,
                            digest,
                            artifact_id=context.artifact_id() or "unknown",
                            snapshot_id=context.snapshot_id(),
                            description=f"Unexpected {magic} binary detected",
                        )
                    ],
                )
            )
            if len(findings) >= context.max_findings_per_rule:
                return findings
        return findings


def _detect_magic(data: bytes) -> str | None:
    for name, magic in BINARY_MAGICS.items():
        if data.startswith(magic):
            return name
    return None


def _previous_paths(context: AnalysisContext) -> set[str]:
    if "from" not in context.snapshot_roots:
        return set()
    return {match.relative_path for match in context.walker("from").iter_files(include_binary=True)}
