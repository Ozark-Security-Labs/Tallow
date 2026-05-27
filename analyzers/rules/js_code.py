"""Lightweight JavaScript lexical masking helpers for line-oriented rules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class JSCodeState:
    in_block_comment: bool = False
    quote: str | None = None
    escaped: bool = False


def js_line_masks(
    line: str,
    state: JSCodeState | None = None,
) -> tuple[list[bool], list[bool], JSCodeState]:
    """Return code and string masks while carrying block/template state."""

    current = state or JSCodeState()
    in_block_comment = current.in_block_comment
    quote = current.quote
    escaped = current.escaped
    code_mask = [False] * len(line)
    string_mask = [False] * len(line)
    index = 0
    while index < len(line):
        char = line[index]
        if in_block_comment:
            if char == "*" and index + 1 < len(line) and line[index + 1] == "/":
                in_block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            string_mask[index] = True
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
            string_mask[index] = True
            index += 1
            continue
        if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            break
        if char == "/" and index + 1 < len(line) and line[index + 1] == "*":
            in_block_comment = True
            index += 2
            continue
        code_mask[index] = True
        index += 1
    return code_mask, string_mask, JSCodeState(in_block_comment, quote, escaped)


def position_in_mask(mask: list[bool], position: int) -> bool:
    return 0 <= position < len(mask) and mask[position]


def range_in_mask(mask: list[bool], start: int, end: int) -> bool:
    return 0 <= start < end <= len(mask) and all(mask[start:end])
