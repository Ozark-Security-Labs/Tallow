import json
from pathlib import Path

import pytest

from tallow_analyzer_sdk.contracts import (
    ValidationError,
    validate_analyzer_input,
    validate_analyzer_output,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = REPO_ROOT / "schemas" / "examples"


def test_valid_example_input():
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    validate_analyzer_input(payload)


def test_missing_required_input_field():
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    payload.pop("job_id")
    with pytest.raises(ValidationError):
        validate_analyzer_input(payload)


def test_incomplete_input_contract_fails():
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    payload.pop("options")
    with pytest.raises(ValidationError):
        validate_analyzer_input(payload)


def test_snapshot_subject_requires_version():
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    payload["analysis_type"] = "snapshot"
    payload["subject"].pop("version", None)
    payload["subject"].pop("to_version", None)
    payload["subject"].pop("from_version", None)
    payload["artifacts"].pop("from")
    payload["snapshot_refs"].pop("from")
    with pytest.raises(ValidationError):
        validate_analyzer_input(payload)
    payload["subject"]["version"] = "1.0.0"
    validate_analyzer_input(payload)


def test_snapshot_diff_subject_requires_to_version_not_version():
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    payload["subject"]["version"] = None
    validate_analyzer_input(payload)
    payload["subject"].pop("to_version")
    with pytest.raises(ValidationError):
        validate_analyzer_input(payload)
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    payload["artifacts"]["to"].pop("filename")
    with pytest.raises(ValidationError):
        validate_analyzer_input(payload)
    payload = json.loads((EXAMPLES / "analyzer-input.snapshot-diff.npm.json").read_text())
    payload["artifacts"]["to"].pop("sha256")
    with pytest.raises(ValidationError):
        validate_analyzer_input(payload)


def test_valid_example_output():
    payload = json.loads((EXAMPLES / "analyzer-output.findings.npm.json").read_text())
    validate_analyzer_output(payload)


def test_output_missing_evidence_fails():
    payload = json.loads((EXAMPLES / "analyzer-output.findings.npm.json").read_text())
    payload["findings"][0]["evidence"] = []
    with pytest.raises(ValidationError):
        validate_analyzer_output(payload)


def test_output_excerpt_requires_redaction_status():
    payload = json.loads((EXAMPLES / "analyzer-output.findings.npm.json").read_text())
    payload["findings"][0]["evidence"][0].pop("excerpt_redacted")
    with pytest.raises(ValidationError):
        validate_analyzer_output(payload)
