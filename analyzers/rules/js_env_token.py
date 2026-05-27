"""Detect suspicious environment and credential access in JavaScript."""

from __future__ import annotations

import re
from collections.abc import Iterable

from rules.js_code import JSCodeState, js_line_masks, position_in_mask, range_in_mask
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
            state = JSCodeState()
            for line_no, line in enumerate(text.splitlines(), start=1):
                code_mask, string_mask, state = js_line_masks(line, state)
                if not any(code_mask):
                    continue
                env_match = _env_token_match(line, code_mask)
                cred_match = _credential_path_read_match(line, code_mask, string_mask)
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
            if position_in_mask(code_mask, match.start()) and _token_like(match.group(1)):
                return match
    return None


def _credential_path_read_match(
    line: str,
    code_mask: list[bool],
    string_mask: list[bool],
) -> bool:
    searchable_mask = [code or string for code, string in zip(code_mask, string_mask, strict=True)]
    for pattern in READ_PATTERNS:
        for read_match in re.finditer(re.escape(pattern), line, flags=re.I):
            if not position_in_mask(code_mask, read_match.start()):
                continue
            open_paren = _next_code_open_paren(line, code_mask, read_match.end())
            if open_paren is None:
                continue
            close_paren = _matching_code_close_paren(line, code_mask, open_paren)
            if _call_contains_credential_path(line, searchable_mask, open_paren + 1, close_paren):
                return True
    return False


def _next_code_open_paren(line: str, code_mask: list[bool], start: int) -> int | None:
    for index in range(start, len(line)):
        if not position_in_mask(code_mask, index):
            continue
        if line[index] == "(":
            return index
        if not line[index].isspace():
            return None
    return None


def _matching_code_close_paren(line: str, code_mask: list[bool], open_paren: int) -> int:
    depth = 1
    for index in range(open_paren + 1, len(line)):
        if not position_in_mask(code_mask, index):
            continue
        if line[index] == "(":
            depth += 1
        elif line[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(line)


def _call_contains_credential_path(
    line: str,
    searchable_mask: list[bool],
    start: int,
    end: int,
) -> bool:
    for pattern in CREDENTIAL_PATH_PATTERNS:
        for match in pattern.finditer(line, start, end):
            if range_in_mask(searchable_mask, match.start(), match.end()):
                return True
    return False


