from pathlib import Path

from rules.py_decode_exec import PyDecodeExecRule
from rules.registry import build_registry
from tallow_analyzer_sdk.constants import DETERMINISTIC_FINDING_CREATED_AT
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.finding import build_finding


def _run(root: Path):
    payload = {
        "contract_version": "v1",
        "job_id": "job_py_decode",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": "pypi", "package_name": "pkg", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_pkg"}},
        "snapshot_refs": {
            "to": {
                "snapshot_id": "snap_pkg",
                "root": str(root),
                "manifest_path": str(root / "manifest.json"),
            }
        },
    }
    return list(PyDecodeExecRule().evaluate(AnalysisContext.from_input(payload)))


def _write(root: Path, text: str) -> None:
    (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (root / "runner.py").write_text(text, encoding="utf-8")


def test_detects_direct_decode_exec(tmp_path: Path):
    _write(tmp_path, "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")
    findings = _run(tmp_path)
    assert findings[0].confidence == "high"
    assert findings[0].evidence[0]["start_line"] == 2


def test_detects_decode_variable_import_sink(tmp_path: Path):
    _write(tmp_path, "import base64\nname = base64.b64decode('b3M=').decode()\n__import__(name)\n")
    findings = _run(tmp_path)
    assert findings[0].confidence == "medium"


def test_detects_marshal_loads_function_type_sink(tmp_path: Path):
    _write(
        tmp_path,
        "import marshal, types\ncode = marshal.loads(b'tallow_test_code')\n"
        "types.FunctionType(code, globals())\n",
    )
    findings = _run(tmp_path)
    assert findings[0].confidence == "high"


def test_benign_encoded_data_does_not_emit(tmp_path: Path):
    _write(tmp_path, "import base64\ndata = base64.b64decode('ZGF0YQ==')\nprint(data)\n")
    assert _run(tmp_path) == []


def test_same_line_decode_exec_sinks_have_distinct_finding_ids(tmp_path: Path):
    _write(
        tmp_path,
        "import base64\n"
        "exec(base64.b64decode('cHJpbnQoMSk=')); exec(base64.b64decode('cHJpbnQoMik='))\n",
    )
    findings = [
        build_finding(draft, created_at=DETERMINISTIC_FINDING_CREATED_AT)
        for draft in _run(tmp_path)
    ]
    assert len({finding["id"] for finding in findings}) == len(findings) == 2


def test_registry_enables_decode_exec_rule_for_pypi_diff_jobs():
    rule_ids = {
        rule.metadata.rule_id for rule in build_registry().enabled_for("pypi", "snapshot_diff")
    }
    assert "py.obfuscation.decode_exec_chain" in rule_ids
