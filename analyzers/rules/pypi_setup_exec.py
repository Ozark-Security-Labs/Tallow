"""Detect execution sinks in Python packaging setup files."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.rules import RuleMetadata

EXEC_NAMES = {
    ("os", "system"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
}
BUILTIN_EXEC = {"eval", "exec"}
SAFE_BUILD_BACKENDS = (
    "setuptools.build_meta",
    "flit_core.buildapi",
    "poetry.core.masonry.api",
    "hatchling.build",
    "pdm.backend",
    "maturin",
    "mesonpy",
    "scikit_build_core.build",
)


class PypiSetupExecRule:
    metadata = RuleMetadata(
        rule_id="pypi.setup.exec_call",
        version="1.0.0",
        name="pypi setup execution sink",
        description="Detect execution sinks in Python packaging setup files.",
        category="script",
        ecosystems=("pypi",),
        default_severity_hint="high",
        default_confidence="high",
        inputs=("snapshot",),
        tags=("pypi", "setup"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        if context.ecosystem != "pypi":
            return []
        walker = context.walker("to")
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["setup.py", "**/setup.py"]):
            text = walker.read_text(match.relative_path)
            try:
                tree = ast.parse(text, filename=match.relative_path)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    target = _call_target(node.func)
                    if target in BUILTIN_EXEC or target in EXEC_NAMES:
                        findings.append(
                            FindingDraft(
                                rule=self.metadata,
                                subject=context.subject,
                                title="setup.py execution sink detected",
                                summary=(
                                    f"Execution sink {target} detected in {match.relative_path}."
                                ),
                                evidence=[
                                    file_evidence(
                                        match.relative_path,
                                        artifact_id=context.artifact_id() or "unknown",
                                        snapshot_id=context.snapshot_id(),
                                        start_line=getattr(node, "lineno", 1),
                                        end_line=getattr(
                                            node,
                                            "end_lineno",
                                            getattr(node, "lineno", 1),
                                        ),
                                        snippet=ast.get_source_segment(text, node) or str(target),
                                        description=f"Execution sink {target} in setup.py",
                                    )
                                ],
                            )
                        )
                        if len(findings) >= context.max_findings_per_rule:
                            return findings
        for match in walker.iter_files(["setup.cfg", "**/setup.cfg"]):
            text = walker.read_text(match.relative_path)
            for line_no, line in enumerate(text.splitlines(), start=1):
                if not _cfg_exec_sink(line):
                    continue
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="setup.cfg execution sink detected",
                        summary=f"Execution sink marker detected in {match.relative_path}.",
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=line_no,
                                end_line=line_no,
                                snippet=line.strip(),
                                description="Execution sink marker in setup.cfg",
                            )
                        ],
                        confidence="medium",
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        for match in walker.iter_files(["pyproject.toml", "**/pyproject.toml"]):
            text = walker.read_text(match.relative_path)
            for line_no, line in enumerate(text.splitlines(), start=1):
                if not _pyproject_exec_sink(line):
                    continue
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="pyproject.toml execution hook detected",
                        summary=f"Execution-oriented build hook detected in {match.relative_path}.",
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=line_no,
                                end_line=line_no,
                                snippet=line.strip(),
                                description="Execution-oriented build hook in pyproject.toml",
                            )
                        ],
                        confidence="medium",
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        return findings


def _call_target(node: ast.AST) -> str | tuple[str, str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return ""


def _cfg_exec_sink(line: str) -> bool:
    lowered = line.lower()
    return any(
        marker in lowered
        for marker in ("os.system", "subprocess.", "eval(", "exec(")
    )


def _pyproject_exec_sink(line: str) -> bool:
    lowered = line.lower()
    if any(marker in lowered for marker in ("os.system", "subprocess.", "eval(", "exec(")):
        return True
    if "cmdclass" in lowered or "[tool.setuptools.cmdclass]" in lowered:
        return True
    backend = _build_backend_value(line)
    return backend != "" and not backend.startswith(SAFE_BUILD_BACKENDS)


def _build_backend_value(line: str) -> str:
    stripped = line.strip()
    if not stripped.lower().startswith("build-backend") or "=" not in stripped:
        return ""
    value = stripped.split("=", 1)[1].strip().strip('"\'')
    return value
