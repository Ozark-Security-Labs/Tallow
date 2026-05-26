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
            for line_no, line in enumerate(text.splitlines(), start=1):
                code_line = _strip_js_strings_for_env(line)
                if not code_line.strip() or code_line.strip().startswith("//"):
                    continue
                env_match = None
                for pattern in ENV_PATTERNS:
                    env_match = pattern.search(code_line)
                    if env_match:
                        key = env_match.group(1)
                        if not _token_like(key):
                            env_match = None
                            continue
                        break
                cred_match = next(
                    (p.search(line) for p in CREDENTIAL_PATH_PATTERNS if p.search(line)),
                    None,
                )
                if cred_match and not _looks_like_path_read(line):
                    cred_match = None
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
                                snippet=line.strip()[:240],
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


def _strip_js_strings_for_env(line: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    for char in line:
        if quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = None
            continue
        if char in {'"', "'", "`"}:
            quote = char
            continue
        output.append(char)
    return "".join(output).split("//", 1)[0]


def _looks_like_path_read(line: str) -> bool:
    lowered = line.lower()
    return any(pattern.lower() in lowered for pattern in READ_PATTERNS)
