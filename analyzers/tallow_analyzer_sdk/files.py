"""Bounded snapshot file traversal helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SnapshotFile:
    relative_path: str
    absolute_path: Path
    size_bytes: int


class SnapshotWalker:
    def __init__(self, *, root: Path, max_file_bytes: int, include_binary: bool = False) -> None:
        self.root = root.resolve()
        self.max_file_bytes = max_file_bytes
        self.include_binary = include_binary

    def iter_files(
        self,
        globs: list[str] | None = None,
        include_binary: bool | None = None,
    ) -> list[SnapshotFile]:
        include_bin = self.include_binary if include_binary is None else include_binary
        matches: list[SnapshotFile] = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames.sort()
            filenames.sort()
            current = Path(dirpath)
            for filename in filenames:
                absolute = current / filename
                if absolute.is_symlink():
                    continue
                if not absolute.is_file():
                    continue
                rel = absolute.relative_to(self.root).as_posix()
                if globs and not any(_glob_match(rel, pattern) for pattern in globs):
                    continue
                size = absolute.stat().st_size
                if size > self.max_file_bytes:
                    continue
                if not include_bin and _looks_binary(absolute):
                    continue
                matches.append(
                    SnapshotFile(relative_path=rel, absolute_path=absolute, size_bytes=size)
                )
        return sorted(matches, key=lambda item: item.relative_path)

    def read_text(self, relative_path: str) -> str:
        path = self.root / relative_path
        data = path.read_bytes()[: self.max_file_bytes]
        return data.decode("utf-8", errors="replace")

    def read_bytes(self, relative_path: str, max_bytes: int | None = None) -> bytes:
        limit = max_bytes or self.max_file_bytes
        path = self.root / relative_path
        with path.open("rb") as handle:
            return handle.read(limit)

    @staticmethod
    def line_span_for_offset(text: str, start: int, end: int) -> tuple[int, int]:
        if start < 0 or end < start:
            raise ValueError("invalid byte range")
        line_start = text.count("\n", 0, start) + 1
        line_end = text.count("\n", 0, end) + 1
        return line_start, line_end


def _glob_match(path: str, pattern: str) -> bool:
    from fnmatch import fnmatch

    if "**" in pattern:
        suffix = pattern.split("**/")[-1]
        return (
            fnmatch(path, pattern)
            or fnmatch(path, suffix)
            or path.endswith(f"/{suffix}")
            or path == suffix
        )
    return fnmatch(path, pattern)


def _looks_binary(path: Path) -> bool:
    with path.open("rb") as handle:
        chunk = handle.read(8192)
    if b"\x00" in chunk:
        return True
    text_chars = bytes({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
    nontext = chunk.translate(None, delete=text_chars)
    return bool(nontext)
