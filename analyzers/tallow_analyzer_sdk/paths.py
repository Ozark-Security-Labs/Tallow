"""Snapshot-relative path normalization and validation."""

from __future__ import annotations

import os
import re
from pathlib import PurePosixPath


class PathValidationError(ValueError):
    """Raised when an evidence path is unsafe or invalid."""


_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[/\\]")


def normalize_evidence_path(path: str) -> str:
    if not path or not str(path).strip():
        raise PathValidationError("path must be non-empty")

    normalized = str(path).replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]

    if _WINDOWS_DRIVE.match(normalized):
        raise PathValidationError("absolute paths are not allowed")
    if normalized.startswith("/"):
        raise PathValidationError("absolute paths are not allowed")

    parts = PurePosixPath(normalized).parts
    if ".." in parts:
        raise PathValidationError("path traversal segments are not allowed")

    cleaned = PurePosixPath(normalized).as_posix()
    if cleaned in {".", ""}:
        raise PathValidationError("path must be non-empty")
    return cleaned


def is_doc_path(path: str) -> bool:
    lowered = path.lower()
    basename = os.path.basename(lowered)
    if basename in {"readme", "readme.md", "changelog", "changelog.md", "license", "license.md"}:
        return True
    return any(
        lowered.endswith(ext)
        for ext in (".md", ".txt", ".rst", ".adoc", ".markdown")
    ) or "/docs/" in lowered or lowered.startswith("docs/")
