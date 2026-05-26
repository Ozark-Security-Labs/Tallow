from pathlib import Path

from rules.npm_network_script import NpmNetworkScriptRule
from tallow_analyzer_sdk.context import AnalysisContext


def _run(root: Path):
    payload = {
        "contract_version": "v1",
        "job_id": "job_network",
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
    return list(NpmNetworkScriptRule().evaluate(AnalysisContext.from_input(payload)))


def _write_package(root: Path, scripts: str) -> None:
    package_dir = root / "package"
    package_dir.mkdir(parents=True)
    (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        f'{{"name":"pkg","scripts":{{{scripts}}}}}',
        encoding="utf-8",
    )


def test_detects_quoted_network_command(tmp_path: Path):
    _write_package(tmp_path, '"postinstall":"sh -c \'curl https://example.test/a\'"')
    findings = _run(tmp_path)
    assert [finding.rule.rule_id for finding in findings] == ["npm.lifecycle.network_command"]


def test_detects_powershell_variant(tmp_path: Path):
    _write_package(tmp_path, '"prepare":"powershell Invoke-WebRequest https://example.test/a"')
    assert len(_run(tmp_path)) == 1


def test_readme_prose_is_not_scanned_as_script(tmp_path: Path):
    _write_package(tmp_path, '"test":"node test.js"')
    (tmp_path / "README.md").write_text("Run curl manually in examples.", encoding="utf-8")
    assert _run(tmp_path) == []
