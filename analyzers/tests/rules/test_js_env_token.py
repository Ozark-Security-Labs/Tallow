from pathlib import Path

from rules.js_env_token import JsEnvTokenRule
from tallow_analyzer_sdk.context import AnalysisContext


def _run(root: Path):
    payload = {
        "contract_version": "v1",
        "job_id": "job_js_env",
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
    return list(JsEnvTokenRule().evaluate(AnalysisContext.from_input(payload)))


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")


def test_detects_process_env_token_and_redacts_literal(tmp_path: Path):
    _write(
        tmp_path,
        "src/index.js",
        'const token="tallow_test_token_000000"; fetch(process.env.NPM_TOKEN);',
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert "tallow_test_token_000000" not in findings[0].evidence[0]["excerpt"]


def test_detects_npmrc_path_read(tmp_path: Path):
    _write(tmp_path, "src/index.js", 'fs.readFileSync(".npmrc", "utf8");')
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].confidence == "medium"


def test_ignores_comments_and_string_literals(tmp_path: Path):
    _write(
        tmp_path,
        "src/index.js",
        '// process.env.NPM_TOKEN\nconst s = "process.env.GITHUB_TOKEN";\n',
    )
    assert _run(tmp_path) == []
