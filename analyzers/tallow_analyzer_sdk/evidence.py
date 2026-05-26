"""Evidence object builders."""

from __future__ import annotations

from typing import Any

from tallow_analyzer_sdk.paths import PathValidationError, normalize_evidence_path
from tallow_analyzer_sdk.redaction import MAX_EXCERPT_LEN, hash_sensitive_value, redact_text


class EvidenceValidationError(ValueError):
    """Raised when evidence coordinates or paths are invalid."""


def _validate_range(start: int | None, end: int | None, label: str) -> None:
    if start is None or end is None:
        return
    if start < 0 or end < 0:
        raise EvidenceValidationError(f"{label} must be non-negative")
    if start > end:
        raise EvidenceValidationError(f"{label} start must be <= end")


def _base_evidence(**fields: Any) -> dict:
    cleaned = {key: value for key, value in fields.items() if value is not None}
    if "path" in cleaned:
        cleaned["path"] = normalize_evidence_path(cleaned["path"])
    return cleaned


def file_evidence(
    path: str,
    *,
    snapshot_id: str | None = None,
    artifact_id: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
    start_byte: int | None = None,
    end_byte: int | None = None,
    snippet: str | None = None,
    description: str | None = None,
) -> dict:
    if artifact_id is None:
        raise EvidenceValidationError("artifact_id is required for file evidence")
    _validate_range(start_line, end_line, "line range")
    _validate_range(start_byte, end_byte, "byte range")

    evidence = _base_evidence(
        kind="file",
        artifact_id=artifact_id,
        snapshot_id=snapshot_id,
        path=path,
        start_line=start_line,
        end_line=end_line,
        start_byte=start_byte,
        end_byte=end_byte,
        description=description,
    )
    if snippet is not None:
        excerpt, redacted = redact_text(snippet, max_len=MAX_EXCERPT_LEN)
        evidence["excerpt"] = excerpt
        evidence["excerpt_redacted"] = redacted
    return evidence


def metadata_evidence(
    key: str,
    value: str,
    *,
    artifact_id: str,
    description: str | None = None,
) -> dict:
    if not artifact_id:
        raise EvidenceValidationError("artifact_id is required for metadata evidence")
    stored_value = value
    redacted = False
    secret_markers = ("token", "secret", "password", "key")
    if len(value) > 64 or any(token in key.lower() for token in secret_markers):
        stored_value = hash_sensitive_value(value)
        redacted = True
    return _base_evidence(
        kind="metadata",
        artifact_id=artifact_id,
        path=key,
        hash=stored_value,
        description=description or f"metadata key {key}",
        excerpt_redacted=redacted,
    )


def hash_evidence(
    algorithm: str,
    observed: str,
    *,
    claimed: str | None = None,
    artifact_id: str,
    description: str | None = None,
) -> dict:
    if not artifact_id:
        raise EvidenceValidationError("artifact_id is required for hash evidence")
    summary = description or f"{algorithm} hash mismatch"
    evidence = _base_evidence(
        kind="hash",
        artifact_id=artifact_id,
        hash=observed,
        description=summary,
    )
    if claimed is not None:
        evidence["excerpt"] = f"claimed={claimed}; observed={observed}"
        evidence["excerpt_redacted"] = False
    return evidence


def binary_evidence(
    path: str,
    magic: str,
    size_bytes: int,
    sha256: str,
    *,
    artifact_id: str,
    snapshot_id: str | None = None,
    description: str | None = None,
) -> dict:
    if not artifact_id:
        raise EvidenceValidationError("artifact_id is required for binary evidence")
    return _base_evidence(
        kind="file",
        artifact_id=artifact_id,
        snapshot_id=snapshot_id,
        path=path,
        hash=sha256,
        description=description or f"unexpected binary ({magic}, {size_bytes} bytes)",
    )


__all__ = [
    "EvidenceValidationError",
    "PathValidationError",
    "binary_evidence",
    "file_evidence",
    "hash_evidence",
    "metadata_evidence",
]
