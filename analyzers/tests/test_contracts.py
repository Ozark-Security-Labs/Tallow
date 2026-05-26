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


def test_valid_example_output():
    payload = json.loads((EXAMPLES / "analyzer-output.findings.npm.json").read_text())
    validate_analyzer_output(payload)


def test_output_missing_evidence_fails():
    payload = json.loads((EXAMPLES / "analyzer-output.findings.npm.json").read_text())
    payload["findings"][0]["evidence"] = []
    with pytest.raises(ValidationError):
        validate_analyzer_output(payload)
