import json
from pathlib import Path

import pytest

from rules.registry import build_registry
from tallow_analyzer_sdk.canonical_json import canonical_dumps
from tallow_analyzer_sdk.contracts import validate_analyzer_input, validate_analyzer_output
from tallow_analyzers.cli import run_analyzer

FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "analyzer-fixtures"
EXAMPLES = Path(__file__).resolve().parents[2] / "schemas" / "examples"


def _snapshot_input(root: Path, fixture_path: str) -> dict:
    ecosystem = "pypi" if fixture_path.startswith("pypi/") else "npm"
    return {
        "contract_version": "v1",
        "job_id": "job_integration",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": ecosystem, "package_name": "fixture", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_integration"}},
        "snapshot_refs": {
            "to": {
                "snapshot_id": "snap_integration",
                "root": str(root),
                "manifest_path": str(root / "manifest.json"),
            }
        },
        "options": {"max_file_bytes": 65536},
    }


def test_registry_has_all_builtin_rules():
    registry = build_registry()
    assert len(registry.all()) == 9


@pytest.mark.parametrize(
    "fixture_path,rule_id",
    [
        ("npm/lifecycle_suspicious/snapshot", "npm.lifecycle.install_script"),
        ("npm/network_script_suspicious/snapshot", "npm.lifecycle.network_command"),
        ("js/env_token_suspicious/snapshot", "js.secrets.env_token_access"),
        ("js/eval_decode_suspicious/snapshot", "js.obfuscation.eval_decode_chain"),
        ("pypi/setup_exec_suspicious/snapshot", "pypi.setup.exec_call"),
        ("pypi/decode_exec_suspicious/snapshot", "py.obfuscation.decode_exec_chain"),
        ("shared/webhook_suspicious/snapshot", "network.webhook_url"),
        ("shared/binary_suspicious/snapshot", "artifact.binary.unexpected"),
        ("shared/high_entropy_suspicious/snapshot", "artifact.entropy.high_blob"),
    ],
)
def test_positive_fixtures_emit_expected_rule(fixture_path: str, rule_id: str):
    root = FIXTURES / fixture_path
    output = run_analyzer(_snapshot_input(root, fixture_path))
    rule_ids = {finding["rule_id"] for finding in output["findings"]}
    assert rule_id in rule_ids


def test_integration_output_is_deterministic():
    root = FIXTURES / "npm/lifecycle_suspicious/snapshot"
    payload = _snapshot_input(root, "npm/lifecycle_suspicious/snapshot")
    first = run_analyzer(payload)
    second = run_analyzer(payload)
    assert canonical_dumps(first) == canonical_dumps(second)
    assert first["findings"][0]["created_at"] == "1970-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "fixture_name",
    ["npm-lifecycle-snapshot", "pypi-setup-snapshot"],
)
def test_golden_fixture_inputs_outputs_are_schema_valid_and_deterministic(fixture_name: str):
    input_path = FIXTURES / "inputs" / f"{fixture_name}.json"
    expected_path = FIXTURES / "expected" / f"{fixture_name}.output.json"
    payload_text = input_path.read_text(encoding="utf-8").replace("__FIXTURE_ROOT__", str(FIXTURES))
    payload = json.loads(payload_text)
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    validate_analyzer_input(payload)
    first = run_analyzer(payload)
    second = run_analyzer(payload)
    validate_analyzer_output(first)
    assert canonical_dumps(first) == canonical_dumps(second)
    assert canonical_dumps(first) == canonical_dumps(expected)


def test_diff_input_finding_subject_denormalizes_filter_coordinates():
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    root = FIXTURES / "npm/lifecycle_suspicious/snapshot"
    payload["snapshot_refs"]["to"]["root"] = str(root)
    payload["snapshot_refs"]["to"]["manifest_path"] = str(root / "manifest.json")
    output = run_analyzer(payload)
    subject = output["findings"][0]["subject"]
    assert subject["artifact_id"] == "art_to_01"
    assert subject["snapshot_id"] == "snap_to_01"
    assert subject["from_artifact_id"] == "art_from_01"
    assert subject["to_artifact_id"] == "art_to_01"
