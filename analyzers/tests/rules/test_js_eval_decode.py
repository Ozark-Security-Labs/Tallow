from pathlib import Path

from rules.js_eval_decode import JsEvalDecodeRule
from tallow_analyzer_sdk.context import AnalysisContext


def _run(root: Path):
    payload = {
        "contract_version": "v1",
        "job_id": "job_js_eval",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": "npm", "package_name": "pkg", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_pkg"}},
        "snapshot_refs": {
            "to": {
                "snapshot_id": "snap_pkg",
                "root": str(root),
                "manifest_path": str(root / "manifest.json"),
            }
        },
    }
    return list(JsEvalDecodeRule().evaluate(AnalysisContext.from_input(payload)))


def _write(root: Path, text: str) -> None:
    src = root / "src"
    src.mkdir(parents=True)
    (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (src / "index.js").write_text(text, encoding="utf-8")


def test_detects_eval_atob(tmp_path: Path):
    _write(tmp_path, 'eval(atob("Y29uc29sZS5sb2coMSk="));')
    findings = _run(tmp_path)
    assert findings[0].confidence == "high"
    assert findings[0].evidence[0]["start_line"] == 1


def test_detects_function_buffer_from_base64(tmp_path: Path):
    _write(tmp_path, 'Function(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64"))();')
    assert len(_run(tmp_path)) == 1


def test_redacts_long_secret_before_excerpt_truncation(tmp_path: Path):
    secret = "s" * 300
    _write(
        tmp_path,
        f'eval(atob("Y29uc29sZS5sb2coMSk=")); const cfg = {{"token": "{secret}"}};',
    )
    evidence = _run(tmp_path)[0].evidence[0]
    assert evidence["excerpt_redacted"] is True
    assert "s" * 32 not in evidence["excerpt"]


def test_detects_settimeout_decoded_variable(tmp_path: Path):
    _write(
        tmp_path,
        'const decoded = atob("Y29uc29sZS5sb2coMSk=");\nsetTimeout(decoded);',
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].evidence[0]["start_line"] == 2


def test_benign_base64_data_does_not_emit(tmp_path: Path):
    _write(tmp_path, 'const data = Buffer.from("Y29udGVudA==", "base64");')
    assert _run(tmp_path) == []
