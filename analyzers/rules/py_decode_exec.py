"""Detect Python decode/decompress chains flowing to execution sinks."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.evidence import file_evidence
from tallow_analyzer_sdk.finding import FindingDraft
from tallow_analyzer_sdk.rules import RuleMetadata

DECODERS = {
    ("base64", "b64decode"),
    ("zlib", "decompress"),
    ("marshal", "loads"),
}
EXECS = {"eval", "exec"}
IMPORTS = {"__import__"}


class PyDecodeExecRule:
    metadata = RuleMetadata(
        rule_id="py.obfuscation.decode_exec_chain",
        version="1.0.0",
        name="python decode exec chain",
        description="Detect decode or decompress chains flowing to execution sinks.",
        category="obfuscation",
        ecosystems=("pypi",),
        default_severity_hint="high",
        default_confidence="high",
        inputs=("snapshot", "snapshot_diff"),
        tags=("obfuscation", "python"),
    )

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]:
        if context.ecosystem != "pypi":
            return []
        walker = context.walker("to")
        findings: list[FindingDraft] = []
        for match in walker.iter_files(["**/*.py"]):
            text = walker.read_text(match.relative_path)
            try:
                tree = ast.parse(text, filename=match.relative_path)
            except SyntaxError:
                continue
            decoded_names = _decoder_assignments(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if (
                    not _is_exec_call(node.func)
                    and not _is_import_call(node.func)
                    and not _is_function_type_call(node.func)
                ):
                    continue
                if not any(
                    _contains_decoder(arg) or _contains_decoded_name(arg, decoded_names)
                    for arg in node.args
                ):
                    continue
                confidence = "medium" if _is_import_call(node.func) else "high"
                findings.append(
                    FindingDraft(
                        rule=self.metadata,
                        subject=context.subject,
                        title="python decode execution chain detected",
                        summary=(
                            "Decode/decompress output flows to execution sink in "
                            f"{match.relative_path}."
                        ),
                        evidence=[
                            file_evidence(
                                match.relative_path,
                                artifact_id=context.artifact_id() or "unknown",
                                snapshot_id=context.snapshot_id(),
                                start_line=getattr(node, "lineno", 1),
                                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                                start_byte=_start_byte(text, node),
                                end_byte=_end_byte(text, node),
                                snippet=ast.get_source_segment(text, node) or "exec/decode chain",
                                description="Decode/decompress chain flows to execution sink",
                            )
                        ],
                        confidence=confidence,
                    )
                )
                if len(findings) >= context.max_findings_per_rule:
                    return findings
        return findings


def _is_exec_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in EXECS


def _is_import_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in IMPORTS


def _is_function_type_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id == "types" and node.attr == "FunctionType"
    return isinstance(node, ast.Name) and node.id == "FunctionType"


def _decoder_assignments(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not _contains_decoder(node.value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _contains_decoder(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        target = _call_target(node.func)
        if target in DECODERS:
            return True
    for child in ast.iter_child_nodes(node):
        if _contains_decoder(child):
            return True
    return False


def _contains_decoded_name(node: ast.AST, decoded_names: set[str]) -> bool:
    if isinstance(node, ast.Name) and node.id in decoded_names:
        return True
    return any(_contains_decoded_name(child, decoded_names) for child in ast.iter_child_nodes(node))


def _call_target(node: ast.AST) -> tuple[str, str] | str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return ""


def _start_byte(text: str, node: ast.AST) -> int | None:
    lineno = getattr(node, "lineno", None)
    col = getattr(node, "col_offset", None)
    if lineno is None or col is None:
        return None
    return _line_start_bytes(text)[lineno - 1] + col


def _end_byte(text: str, node: ast.AST) -> int | None:
    lineno = getattr(node, "end_lineno", None)
    col = getattr(node, "end_col_offset", None)
    if lineno is None or col is None:
        return None
    return _line_start_bytes(text)[lineno - 1] + col


def _line_start_bytes(text: str) -> list[int]:
    starts = [0]
    total = 0
    for line in text.splitlines(keepends=True):
        total += len(line.encode("utf-8"))
        starts.append(total)
    return starts
