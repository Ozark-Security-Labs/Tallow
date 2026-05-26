"""Detect high-entropy blobs in text-like package files."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.rules import RuleMetadata

IGNORE_SUFFIXES = (
    ".lock",
    ".min.js",
    ".min.css",
)
IGNORE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}


class HighEntropyBlobRule:
    metadata = RuleMetadata(
        rule_id="artifact.entropy.high_blob",
        version="1.0.0",
        name="high entropy blob",
        description="Detect high-entropy blobs in text-like files.",
        category="obfuscation",
        ecosystems=("npm", "pypi", "*"),
        default_severity_hint="medium",
        default_confidence="medium",
        inputs=("snapshot",),
        tags=("entropy", "obfuscation"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        walker = context.walker("to")
        previous_hashes = _previous_hashes(context)
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["**/*"]):
            if _should_ignore(match.relative_path):
                continue
            text = walker.read_text(match.relative_path)
            if previous_hashes.get(match.relative_path) == _content_hash(text):
                continue
            for window in _entropy_windows(text):
                min_len = int(context.options.get("high_entropy_min_length", 64))
                threshold = float(context.options.get("high_entropy_threshold", 4.5))
                if window["entropy"] < threshold or len(window["value"]) < min_len:
                    continue
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="high entropy blob detected",
                        summary=(
                            f"High-entropy blob detected in {match.relative_path} "
                            f"around line {window['line']}."
                        ),
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=window["line"],
                                end_line=window["line"],
                                description=(
                                    f"Entropy {window['entropy']:.2f} over "
                                    f"{len(window['value'])} chars; "
                                    f"value_sha256={window['value_hash']}"
                                ),
                            )
                        ],
                        confidence="medium",
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        return findings


def _should_ignore(path: str) -> bool:
    basename = path.split("/")[-1]
    if basename in IGNORE_NAMES:
        return True
    return any(path.endswith(suffix) for suffix in IGNORE_SUFFIXES)


def _entropy_windows(text: str) -> list[dict]:
    results: list[dict] = []
    pattern = re.compile(r"[A-Za-z0-9+/=]{64,}")
    for match in pattern.finditer(text):
        value = match.group(0)
        entropy = _shannon_entropy(value)
        line = text.count("\n", 0, match.start()) + 1
        from tallow_analyzer_sdk.redaction import hash_sensitive_value

        results.append(
            {
                "value": value,
                "value_hash": hash_sensitive_value(value),
                "entropy": entropy,
                "line": line,
            }
        )
    return results


def _previous_hashes(context: AnalysisContext) -> dict[str, str]:
    if "from" not in context.snapshot_roots:
        return {}
    walker = context.walker("from")
    hashes: dict[str, str] = {}
    for match in walker.iter_files(["**/*"]):
        if _should_ignore(match.relative_path):
            continue
        hashes[match.relative_path] = _content_hash(walker.read_text(match.relative_path))
    return hashes


def _content_hash(text: str) -> str:
    from tallow_analyzer_sdk.redaction import hash_sensitive_value

    return hash_sensitive_value(text)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
