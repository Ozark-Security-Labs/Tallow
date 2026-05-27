from pathlib import Path

from rules.npm_lifecycle import NpmLifecycleRule
from tallow_analyzer_sdk.constants import DETERMINISTIC_FINDING_CREATED_AT
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.finding import build_finding

FIXTURES = Path(__file__).resolve().parents[3] / "testdata" / "analyzer-fixtures" / "npm"


def _run_fixture(name: str):
    root = FIXTURES / name / "snapshot"
    payload = {
        "contract_version": "v1",
        "job_id": "job_test",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": "npm", "package_name": name, "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": f"art_{name}"}},
        "snapshot_refs": {
            "to": {
                "snapshot_id": f"snap_{name}",
                "root": str(root),
                "manifest_path": str(root / "manifest.json"),
            }
        },
    }
    context = AnalysisContext.from_input(payload)
    return list(NpmLifecycleRule().evaluate(context))


def _run_snapshot(root: Path):
    payload = {
        "contract_version": "v1",
        "job_id": "job_test",
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
    return list(NpmLifecycleRule().evaluate(AnalysisContext.from_input(payload)))


def test_no_scripts_produces_no_finding():
    assert _run_fixture("lifecycle_absent") == []


def test_benign_scripts_produce_no_finding():
    assert _run_fixture("lifecycle_benign") == []


def test_postinstall_produces_one_finding():
    findings = _run_fixture("lifecycle_suspicious")
    assert len(findings) == 1
    assert findings[0].rule.rule_id == "npm.lifecycle.install_script"


def test_lifecycle_keys_are_detected(tmp_path: Path):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        """
        {
          "name": "lifecycle-all",
          "scripts": {
            "preinstall": "node pre.js",
            "install": "node install.js",
            "postinstall": "node post.js",
            "prepare": "node prepare.js"
          }
        }
        """,
        encoding="utf-8",
    )

    findings = _run_snapshot(tmp_path)
    keys = {finding.tags[-1] for finding in findings}
    assert keys == {"preinstall", "install", "postinstall", "prepare"}
    assert all(finding.rule.rule_id == "npm.lifecycle.install_script" for finding in findings)


def test_same_line_lifecycle_scripts_have_distinct_finding_ids(tmp_path: Path):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        '{"name":"pkg","scripts":{"preinstall":"node pre.js","install":"node install.js"}}',
        encoding="utf-8",
    )
    findings = [
        build_finding(draft, created_at=DETERMINISTIC_FINDING_CREATED_AT)
        for draft in _run_snapshot(tmp_path)
    ]
    assert len({finding["id"] for finding in findings}) == len(findings) == 2


def test_lifecycle_evidence_points_to_scripts_key_not_prior_matching_key(tmp_path: Path):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        '{\n'
        '  "config": {"install": "not a lifecycle script"},\n'
        '  "scripts": {\n'
        '    "install": "node install.js"\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = _run_snapshot(tmp_path)
    assert len(findings) == 1
    evidence = findings[0].evidence[0]
    assert evidence["start_line"] == 4
    assert '"install": "node install.js"' in evidence["excerpt"]
    text = (package_dir / "package.json").read_text(encoding="utf-8")
    assert text.encode("utf-8")[evidence["start_byte"] : evidence["end_byte"]].decode(
        "utf-8"
    ) == '"install": "node install.js"'


def test_lifecycle_evidence_uses_last_duplicate_scripts_semantics(tmp_path: Path):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        '{\n'
        '  "scripts": {"install": "node wrong.js"},\n'
        '  "scripts": {\n'
        '    "install": "",\n'
        '    "install": "node install.js"\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = _run_snapshot(tmp_path)
    assert len(findings) == 1
    evidence = findings[0].evidence[0]
    assert evidence["start_line"] == 5
    assert '"install": "node install.js"' in evidence["excerpt"]


def test_non_object_scripts_does_not_emit(tmp_path: Path):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        '{"scripts": "node install.js"}',
        encoding="utf-8",
    )
    assert _run_snapshot(tmp_path) == []


def test_lifecycle_respects_max_findings_per_rule(tmp_path: Path):
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (package_dir / "package.json").write_text(
        '{"scripts":{"preinstall":"node pre.js","install":"node install.js"}}',
        encoding="utf-8",
    )
    payload = {
        "contract_version": "v1",
        "job_id": "job_test",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": "npm", "package_name": "pkg", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_pkg"}},
        "snapshot_refs": {
            "to": {
                "snapshot_id": "snap_pkg",
                "root": str(tmp_path),
                "manifest_path": str(tmp_path / "manifest.json"),
            }
        },
        "options": {"max_findings_per_rule": 1},
    }
    findings = list(NpmLifecycleRule().evaluate(AnalysisContext.from_input(payload)))
    assert len(findings) == 1


def test_deterministic_output():
    first = _run_fixture("lifecycle_suspicious")
    second = _run_fixture("lifecycle_suspicious")
    assert first[0].title == second[0].title
