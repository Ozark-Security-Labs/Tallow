#!/usr/bin/env python3
"""Safety lint for inert synthetic Tallow fixtures."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 5 * 1024 * 1024
ALLOWLIST_NAME = "fixture-safety.json"

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(
        r"(?i)(?:token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?"
        r"(?!process\.env\b)[A-Za-z0-9._\-/+=]{12,}"
    ),
)

FAKE_MARKERS = (
    "fake",
    "synthetic",
    "example.test",
    "tallow_test_",
    "000000",
    "not-a-real-secret",
)

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}


def load_allowlist(root: Path) -> dict[str, set[str]]:
    path = root / ALLOWLIST_NAME
    if not path.exists():
        return {"executable": set(), "secrets": set()}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return {
        "executable": set(_list(payload, "allowed_executable_paths")),
        "secrets": set(_list(payload, "allowed_secret_paths")),
    }


def _list(payload: dict[str, Any], key: str) -> list[str]:
    values = payload.get(key, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"{key} must be a list of strings")
    return sorted(values)


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and not path.is_symlink():
            files.append(path)
    return files


def lint_root(root: Path) -> list[str]:
    errors: list[str] = []
    allowlist = load_allowlist(root)
    total = 0
    for path in iter_files(root):
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        total += size
        if size > MAX_FILE_BYTES:
            errors.append(f"{path}: fixture exceeds {MAX_FILE_BYTES} bytes")
        if _is_executable(path) and rel not in allowlist["executable"]:
            errors.append(f"{path}: executable bit requires {ALLOWLIST_NAME} documentation")
        data = path.read_bytes()
        if _has_secret(data) and rel not in allowlist["secrets"] and not _marked_fake(data):
            errors.append(f"{path}: real-looking secret requires fake marker or allowlist")
    if total > MAX_TOTAL_BYTES:
        errors.append(f"{root}: fixtures exceed total size limit {MAX_TOTAL_BYTES} bytes")
    return errors


def _is_executable(path: Path) -> bool:
    return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _has_secret(data: bytes) -> bool:
    text = data[:MAX_FILE_BYTES].decode("utf-8", errors="ignore")
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def _marked_fake(data: bytes) -> bool:
    text = data[:MAX_FILE_BYTES].decode("utf-8", errors="ignore").lower()
    return any(marker in text for marker in FAKE_MARKERS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint Tallow fixture safety constraints")
    parser.add_argument("paths", nargs="+", type=Path, help="fixture roots to scan")
    args = parser.parse_args(argv)
    errors: list[str] = []
    for root in args.paths:
        if not root.exists():
            errors.append(f"{root}: path does not exist")
            continue
        errors.extend(lint_root(root))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Fixture safety lint passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
