import json
import subprocess
import sys
from pathlib import Path

from tallow_analyzer_sdk.canonical_json import strip_runtime_fields
from tallow_analyzers.cli import main, run_analyzer

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_INPUT = REPO_ROOT / "schemas" / "examples" / "analyzer-input.snapshot-diff.npm.json"
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "snapshots" / "simple_npm"


def _input_with_fixture_root() -> dict:
    payload = json.loads(EXAMPLE_INPUT.read_text())
    payload["options"]["enabled_rules"] = []
    payload["options"]["max_file_bytes"] = 4096
    payload["snapshot_refs"]["to"]["root"] = str(FIXTURE_ROOT)
    payload["snapshot_refs"]["to"]["manifest_path"] = str(FIXTURE_ROOT / "manifest.json")
    return payload


def test_list_rules_sorted(capsys):
    assert main(["--list-rules"]) == 0
    payload = json.loads(capsys.readouterr().out)
    rule_ids = [item["rule_id"] for item in payload]
    assert rule_ids == sorted(rule_ids)


def test_valid_empty_fixture_produces_ok_status():
    output = run_analyzer(_input_with_fixture_root())
    assert output["status"] == "ok"
    assert output["findings"] == []


def test_hash_verification_input_does_not_run_snapshot_rules():
    payload = json.loads(EXAMPLE_INPUT.read_text())
    payload["job_id"] = "job_hash"
    payload["analysis_type"] = "hash_verification"
    payload.pop("snapshot_refs")
    payload["artifacts"] = {"to": payload["artifacts"]["to"]}
    payload["hash_verification"] = {
        "artifact_id": payload["artifacts"]["to"]["artifact_id"],
        "expected_sha256": "a" * 64,
        "observed_sha256": "b" * 64,
        "source": "registry",
    }
    output = run_analyzer(payload)
    assert output["status"] == "ok"
    assert output["metrics"]["rules_evaluated"] == 0
    assert output["errors"] == []


def test_invalid_input_exits_non_zero(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["--input", str(bad), "--output", str(tmp_path / "out.json")]) == 2


def test_deterministic_output_after_strip_runtime_fields():
    payload = _input_with_fixture_root()
    first = strip_runtime_fields(run_analyzer(payload))
    second = strip_runtime_fields(run_analyzer(payload))
    assert first == second


def test_module_invocation_list_rules():
    completed = subprocess.run(
        [sys.executable, "-m", "tallow_analyzers.cli", "--list-rules"],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
