"""Location helpers for package.json rules."""

from __future__ import annotations

import json


def span_for_script_key(text: str, key: str) -> tuple[int, int, int]:
    root_start = text.find("{")
    if root_start < 0:
        return 1, 0, 0
    root_end = _matching_delimiter(text, root_start, "{", "}")
    if root_end is None:
        return 1, 0, 0
    for prop in reversed(_object_properties(text, root_start, root_end)):
        if prop.key != "scripts" or prop.value_start >= len(text) or text[prop.value_start] != "{":
            continue
        scripts_end = _matching_delimiter(text, prop.value_start, "{", "}")
        if scripts_end is None:
            continue
        for script_prop in reversed(_object_properties(text, prop.value_start, scripts_end)):
            if script_prop.key == key:
                return _line_byte_span(text, script_prop.key_start, script_prop.colon + 1)
    return 1, 0, 0


class _Property:
    def __init__(
        self,
        *,
        key: str,
        key_start: int,
        colon: int,
        value_start: int,
        value_end: int,
    ) -> None:
        self.key = key
        self.key_start = key_start
        self.colon = colon
        self.value_start = value_start
        self.value_end = value_end


def _object_properties(text: str, start: int, end: int) -> list[_Property]:
    props: list[_Property] = []
    index = start + 1
    while index < end:
        index = _skip_ws_and_commas(text, index, end)
        if index >= end or text[index] != '"':
            break
        key_start = index
        key_end = _string_end(text, key_start)
        if key_end is None:
            break
        key = json.loads(text[key_start:key_end])
        colon = _skip_ws(text, key_end, end)
        if colon >= end or text[colon] != ":":
            break
        value_start = _skip_ws(text, colon + 1, end)
        value_end = _value_end(text, value_start, end)
        props.append(
            _Property(
                key=key,
                key_start=key_start,
                colon=colon,
                value_start=value_start,
                value_end=value_end,
            )
        )
        index = value_end
    return props


def _skip_ws(text: str, index: int, end: int) -> int:
    while index < end and text[index].isspace():
        index += 1
    return index


def _skip_ws_and_commas(text: str, index: int, end: int) -> int:
    while index < end and (text[index].isspace() or text[index] == ","):
        index += 1
    return index


def _value_end(text: str, start: int, end: int) -> int:
    if start >= end:
        return start
    char = text[start]
    if char == '"':
        return _string_end(text, start) or start
    if char == "{":
        return (_matching_delimiter(text, start, "{", "}") or start) + 1
    if char == "[":
        return (_matching_delimiter(text, start, "[", "]") or start) + 1
    index = start
    while index < end and text[index] not in ",}":
        index += 1
    return index


def _string_end(text: str, start: int) -> int | None:
    escaped = False
    for index in range(start + 1, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index + 1
    return None


def _matching_delimiter(text: str, start: int, open_char: str, close_char: str) -> int | None:
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
    return None


def _line_byte_span(text: str, start: int, end: int) -> tuple[int, int, int]:
    return (
        text.count("\n", 0, start) + 1,
        len(text[:start].encode("utf-8")),
        len(text[:end].encode("utf-8")),
    )
