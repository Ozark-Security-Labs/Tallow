"""Detect high-entropy blobs in text-like package files."""

from __future__ import annotations

import hashlib
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
        inputs=("snapshot", "snapshot_diff"),
        tags=("entropy", "obfuscation"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        walker = context.walker("to")
        min_len = int(context.options.get("high_entropy_min_length", 512))
        threshold = float(context.options.get("high_entropy_threshold", 7.2))
        previous_window_hashes = _previous_window_hashes(context, min_len=min_len)
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["**/*"]):
            if _should_ignore(match.relative_path):
                continue
            data = walker.read_bytes(match.relative_path)
            for window in _entropy_windows(data, min_len=min_len):
                if window["value_hash"] in previous_window_hashes.get(match.relative_path, set()):
                    continue
                if window["entropy"] < threshold or window["length"] < min_len:
                    continue
                evidence = file_evidence(
                    match.relative_path,
                    artifact_id=context.artifact_id() or "unknown",
                    snapshot_id=context.snapshot_id(),
                    start_line=window["line"],
                    end_line=window["line"],
                    start_byte=window["start_byte"],
                    end_byte=window["end_byte"],
                    description=(
                        f"Entropy {window['entropy']:.3f} over {window['length']} bytes; "
                        f"sha256={window['value_hash']}"
                    ),
                )
                evidence["sha256"] = window["value_hash"]
                evidence["hash"] = window["value_hash"]
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="high entropy blob detected",
                        summary=(
                            f"High-entropy blob detected in {match.relative_path} "
                            f"around line {window['line']}."
                        ),
                        evidence=[evidence],
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


def _entropy_windows(data: bytes, *, min_len: int) -> list[dict]:
    results: list[dict] = []
    pattern = re.compile(rb"\S{%d,}" % min_len)
    for match in pattern.finditer(data):
        value = match.group(0)
        entropy = _shannon_entropy(value)
        line = data.count(b"\n", 0, match.start()) + 1
        results.append(
            {
                "length": len(value),
                "value_hash": _content_hash(value),
                "entropy": entropy,
                "line": line,
                "start_byte": match.start(),
                "end_byte": match.end(),
            }
        )
    return results


def _previous_window_hashes(context: AnalysisContext, *, min_len: int) -> dict[str, set[str]]:
    if "from" not in context.snapshot_roots:
        return {}
    walker = context.walker("from")
    hashes: dict[str, set[str]] = {}
    for match in walker.iter_files(["**/*"]):
        if _should_ignore(match.relative_path):
            continue
        data = walker.read_bytes(match.relative_path)
        hashes[match.relative_path] = {
            window["value_hash"] for window in _entropy_windows(data, min_len=min_len)
        }
    return hashes


def _content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _shannon_entropy(value: bytes) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
