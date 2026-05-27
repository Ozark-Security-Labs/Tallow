"""Detect suspicious environment and credential access in JavaScript."""

from __future__ import annotations

import re
from collections.abc import Iterable

from tallow_analyzer_sdk.constants import EXECUTABLE_EXTENSIONS
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.paths import is_doc_path
from tallow_analyzer_sdk.rules import RuleMetadata

ENV_PATTERNS = (
    re.compile(r'process\.env\.([A-Z0-9_]+)', re.I),
    re.compile(r'process\.env\[["\']([^"\']+)["\']\]', re.I),
)
CREDENTIAL_PATH_PATTERNS = (
    re.compile(r"\.npmrc"),
    re.compile(r"\.ssh/"),
    re.compile(r"id_rsa"),
    re.compile(r"known_hosts"),
)
READ_PATTERNS = (
    "readfilesync",
    "readfile",
    "createReadStream",
)


class JsEnvTokenRule:
    metadata = RuleMetadata(
        rule_id="js.secrets.env_token_access",
        version="1.0.0",
        name="javascript env token access",
        description="Detect suspicious environment token and credential path access in JavaScript.",
        category="credential",
        ecosystems=("npm", "pypi", "*"),
        default_severity_hint="high",
        default_confidence="medium",
        inputs=("snapshot", "snapshot_diff"),
        tags=("credential", "javascript"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        walker = context.walker("to")
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"]):
            if match.relative_path.endswith(".d.ts") or is_doc_path(match.relative_path):
                continue
            if not any(match.relative_path.endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
                continue
            text = walker.read_text(match.relative_path)
            in_block_comment = False
            for line_no, line in enumerate(text.splitlines(), start=1):
                code_mask, in_block_comment = _js_code_mask(line, in_block_comment)
                if not any(code_mask):
                    continue
                env_match = _env_token_match(line, code_mask)
                cred_match = _credential_path_read_match(line, code_mask)
                if not env_match and not cred_match:
                    continue
                summary = (
                    f"Suspicious process.env access in {match.relative_path}"
                    if env_match
                    else f"Credential path reference in {match.relative_path}"
                )
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="javascript credential access detected",
                        summary=summary,
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=line_no,
                                end_line=line_no,
                                snippet=line.strip(),
                                description=summary,
                            )
                        ],
                        confidence="high" if env_match else "medium",
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        return findings


def _token_like(key: str) -> bool:
    upper = key.upper()
    markers = ("TOKEN", "SECRET", "KEY", "AWS_", "NPM_TOKEN", "GITHUB_TOKEN", "CI_JOB_TOKEN")
    return any(token in upper for token in markers)


def _env_token_match(line: str, code_mask: list[bool]) -> re.Match[str] | None:
    for pattern in ENV_PATTERNS:
        for match in pattern.finditer(line):
            if _position_in_code_mask(code_mask, match.start()) and _token_like(match.group(1)):
                return match
    return None


def _credential_path_read_match(line: str, code_mask: list[bool]) -> re.Match[str] | None:
    read_in_code = any(
        _position_in_code_mask(code_mask, match.start())
        for pattern in READ_PATTERNS
        for match in re.finditer(re.escape(pattern), line, flags=re.I)
    )
    if not read_in_code:
        return None
    return next(
        (pattern.search(line) for pattern in CREDENTIAL_PATH_PATTERNS if pattern.search(line)),
        None,
    )


def _position_in_code_mask(code_mask: list[bool], position: int) -> bool:
    return 0 <= position < len(code_mask) and code_mask[position]


def _js_code_mask(line: str, in_block_comment: bool = False) -> tuple[list[bool], bool]:
    code_mask = [False] * len(line)
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if in_block_comment:
            if char == "*" and index + 1 < len(line) and line[index + 1] == "/":
                in_block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
            index += 1
            continue
        if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            break
        if char == "/" and index + 1 < len(line) and line[index + 1] == "*":
            in_block_comment = True
            index += 2
            continue
        code_mask[index] = True
        index += 1
    return code_mask, in_block_comment


