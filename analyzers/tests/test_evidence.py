import pytest

from tallow_analyzer_sdk.evidence import (
    EvidenceValidationError,
    file_evidence,
    hash_evidence,
    metadata_evidence,
)
from tallow_analyzer_sdk.paths import PathValidationError, normalize_evidence_path


def test_reject_absolute_path():
    with pytest.raises(PathValidationError):
        normalize_evidence_path("/etc/passwd")


def test_reject_traversal():
    with pytest.raises(PathValidationError):
        normalize_evidence_path("../secret")


def test_normalize_windows_separators():
    assert normalize_evidence_path(".\\package\\file.js") == "package/file.js"


def test_line_range_validation():
    with pytest.raises(EvidenceValidationError):
        file_evidence("package.json", artifact_id="a", start_line=5, end_line=2)


def test_snippet_redaction_and_bound():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet='token="super-secret-value-here"',
    )
    assert evidence["excerpt_redacted"] is True
    assert len(evidence["excerpt"]) <= 240


def test_metadata_hashes_secret_like_values():
    evidence = metadata_evidence("npm_token", "super-secret-token-value", artifact_id="a")
    assert evidence["hash"] != "super-secret-token-value"
    assert evidence["excerpt_redacted"] is True


def test_hash_evidence():
    evidence = hash_evidence(
        "sha256",
        "abc",
        claimed="def",
        artifact_id="a",
        description="hash mismatch",
    )
    assert evidence["kind"] == "hash"
