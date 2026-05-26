from pathlib import Path

from rules.npm_lifecycle import NpmLifecycleRule
from tallow_analyzer_sdk.context import AnalysisContext

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


def test_no_scripts_produces_no_finding():
    assert _run_fixture("lifecycle_absent") == []


def test_benign_scripts_produce_no_finding():
    assert _run_fixture("lifecycle_benign") == []


def test_postinstall_produces_one_finding():
    findings = _run_fixture("lifecycle_suspicious")
    assert len(findings) == 1
    assert findings[0].rule.rule_id == "npm.lifecycle.install_script"


def test_deterministic_output():
    first = _run_fixture("lifecycle_suspicious")
    second = _run_fixture("lifecycle_suspicious")
    assert first[0].title == second[0].title
