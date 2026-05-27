from pathlib import Path

from rules.npm_network_script import NpmNetworkScriptRule
from tallow_analyzer_sdk.constants import DETERMINISTIC_FINDING_CREATED_AT
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.finding import build_finding


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


def test_same_line_network_scripts_have_distinct_finding_ids(tmp_path: Path):
    _write_package(
        tmp_path,
        '"preinstall":"curl https://example.test/a","postinstall":"wget https://example.test/b"',
    )
    findings = [
        build_finding(draft, created_at=DETERMINISTIC_FINDING_CREATED_AT)
        for draft in _run(tmp_path)
    ]
    assert len({finding["id"] for finding in findings}) == len(findings) == 2


def test_network_evidence_points_to_scripts_key_not_prior_matching_key(tmp_path: Path):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        '{\n'
        '  "metadata": {"postinstall": "curl https://example.test/not-script"},\n'
        '  "scripts": {\n'
        '    "postinstall": "curl https://example.test/script"\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    evidence = findings[0].evidence[0]
    assert evidence["start_line"] == 4
    assert '"postinstall": "curl https://example.test/script"' in evidence["excerpt"]
