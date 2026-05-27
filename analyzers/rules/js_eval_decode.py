"""Detect JavaScript decode-to-execution obfuscation chains."""

from __future__ import annotations

import re
from collections.abc import Iterable

from rules.js_code import JSCodeState, js_line_masks, position_in_mask
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.paths import is_doc_path
from tallow_analyzer_sdk.rules import RuleMetadata

PATTERNS = (
    re.compile(r"eval\s*\(\s*atob\s*\(", re.I),
    re.compile(r"Function\s*\(\s*atob\s*\(", re.I),
    re.compile(r"eval\s*\(\s*Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]\)", re.I),
    re.compile(r"Function\s*\(\s*Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]\)", re.I),
    re.compile(r"new\s+Function\s*\(.*(?:atob|base64)", re.I),
    re.compile(r"setTimeout\s*\(\s*atob\s*\(", re.I),
)
DECODE_ASSIGNMENT_PATTERNS = (
    re.compile(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*atob\s*\(",
        re.I,
    ),
    re.compile(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*Buffer\.from\s*\([^)]*['\"]base64['\"]",
        re.I,
    ),
)


class JsEvalDecodeRule:
    metadata = RuleMetadata(
        rule_id="js.obfuscation.eval_decode_chain",
        version="1.0.0",
        name="javascript eval decode chain",
        description="Detect decode-to-execution chains in JavaScript source.",
        category="obfuscation",
        ecosystems=("npm", "pypi", "*"),
        default_severity_hint="high",
        default_confidence="high",
        inputs=("snapshot", "snapshot_diff"),
        tags=("obfuscation", "javascript"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        walker = context.walker("to")
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"]):
            if match.relative_path.endswith(".d.ts") or is_doc_path(match.relative_path):
                continue
            text = walker.read_text(match.relative_path)
            decoded_vars: set[str] = set()
            state = JSCodeState()
            for line_no, line in enumerate(text.splitlines(), start=1):
                code_mask, _, state = js_line_masks(line, state)
                decoded_vars.update(_decoded_assignments(line, code_mask))
                if not _has_decode_execution(line, decoded_vars, code_mask):
                    continue
                confidence = (
                    "high"
                    if "eval" in line.lower() or "function" in line.lower()
                    else "medium"
                )
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="javascript decode execution chain detected",
                        summary=f"Decode-to-execution pattern detected in {match.relative_path}.",
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=line_no,
                                end_line=line_no,
                                snippet=line.strip(),
                                description="Decode source flows to execution sink",
                            )
                        ],
                        confidence=confidence,
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        return findings


def _decoded_assignments(line: str, code_mask: list[bool]) -> set[str]:
    names: set[str] = set()
    for pattern in DECODE_ASSIGNMENT_PATTERNS:
        for match in pattern.finditer(line):
            if not position_in_mask(code_mask, match.start()):
                continue
            names.add(match.group(1))
    return names


def _has_decode_execution(line: str, decoded_vars: set[str], code_mask: list[bool]) -> bool:
    for pattern in PATTERNS:
        if _search_in_code(pattern, line, code_mask):
            return True
    for name in decoded_vars:
        escaped = re.escape(name)
        if _search_in_code(
            re.compile(rf"(?:eval|setTimeout|setInterval)\s*\(\s*{escaped}\b", re.I),
            line,
            code_mask,
        ):
            return True
        if _search_in_code(
            re.compile(rf"(?:new\s+)?Function\s*\(\s*{escaped}\b", re.I),
            line,
            code_mask,
        ):
            return True
    return False


def _search_in_code(
    pattern: re.Pattern[str], line: str, code_mask: list[bool]
) -> re.Match[str] | None:
    for match in pattern.finditer(line):
        if position_in_mask(code_mask, match.start()):
            return match
    return None
