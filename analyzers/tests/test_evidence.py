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


def test_reject_windows_absolute_path():
    with pytest.raises(PathValidationError):
        normalize_evidence_path("C:\\Users\\operator\\token.txt")


def test_reject_traversal():
    with pytest.raises(PathValidationError):
        normalize_evidence_path("../secret")


def test_normalize_windows_separators():
    assert normalize_evidence_path(".\\package\\file.js") == "package/file.js"


def test_file_evidence_supports_byte_ranges():
    evidence = file_evidence(
        "package/file.js",
        artifact_id="a",
        start_byte=4,
        end_byte=10,
    )
    assert evidence["start_byte"] == 4
    assert evidence["end_byte"] == 10


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


def test_snippet_redacts_bearer_and_single_quoted_tokens():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet="authorization: Bearer abcdefghijklmnop; token='supersecretvalue'",
    )
    assert evidence["excerpt_redacted"] is True
    assert "abcdefghijklmnop" not in evidence["excerpt"]
    assert "supersecretvalue" not in evidence["excerpt"]


def test_snippet_redacts_standalone_known_token_shapes():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet="leaked ghp_abcdefghijklmnopqrstuvwxyz npm_abcdefghijklmnopqrstuv",
    )
    assert evidence["excerpt_redacted"] is True
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in evidence["excerpt"]
    assert "npm_abcdefghijklmnopqrstuv" not in evidence["excerpt"]


def test_snippet_redacts_webhook_url_path_tokens():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet=(
            "postinstall=curl "
            "https://discord.com/api/webhooks/123456789012345678/secret-token?wait=true"
        ),
    )
    assert evidence["excerpt_redacted"] is True
    assert "123456789012345678" not in evidence["excerpt"]
    assert "secret-token" not in evidence["excerpt"]
    assert "wait=true" not in evidence["excerpt"]
    assert "https://discord.com/api/webhooks/<redacted>/<redacted>?<redacted>" in evidence[
        "excerpt"
    ]


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
