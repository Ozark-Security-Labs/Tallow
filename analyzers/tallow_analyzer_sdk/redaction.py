"""Evidence excerpt redaction helpers."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

MAX_EXCERPT_LEN = 240

_TOKEN_PATTERN = re.compile(
    r"(?i)([\"']?(?:token|secret|password|api[_-]?key)[\"']?\s*[:=]\s*)"
    r"(?:([\"'])([^\"'\r\n]{8,})(\3)?|([^\s,\"';})\]]{8,}))"
)
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-+/=]{8,})")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
_URL_QUERY_PATTERN = re.compile(r"(\?)([^#\s]+)")
_STANDALONE_SECRET_PATTERN = re.compile(
    r"\b("
    r"gh[pousr]_[A-Za-z0-9_]{20,}"
    r"|npm_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r")\b"
)


def _redaction_tag(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"<redacted:sha256:{digest}>"


def redact_text(text: str, *, max_len: int = MAX_EXCERPT_LEN) -> tuple[str, bool]:
    redacted = False
    output = text

    def token_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        if match.group(2):
            quote = match.group(2)
            closing_quote = match.group(4) or ""
            return f"{match.group(1)}{quote}{_redaction_tag(match.group(3))}{closing_quote}"
        return f"{match.group(1)}{_redaction_tag(match.group(5))}"

    output = _TOKEN_PATTERN.sub(token_repl, output)

    def bearer_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return f"{match.group(1)}{_redaction_tag(match.group(2))}"

    output = _BEARER_PATTERN.sub(bearer_repl, output)

    def standalone_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return _redaction_tag(match.group(1))

    output = _STANDALONE_SECRET_PATTERN.sub(standalone_repl, output)

    def url_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        original = match.group(0)
        cleaned = redact_url(original)
        if cleaned != original:
            redacted = True
        return cleaned

    output = _URL_PATTERN.sub(url_repl, output)

    def query_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return f"{match.group(1)}<redacted>"

    output = _URL_QUERY_PATTERN.sub(query_repl, output)

    if len(output) > max_len:
        output = output[: max_len - 3] + "..."
        redacted = True

    return output, redacted


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    path = _redact_url_path((parts.hostname or "").lower(), parts.path)
    query = "<redacted>" if parts.query else ""
    return urlunsplit((parts.scheme, _redact_url_netloc(parts.netloc), path, query, parts.fragment))


def _redact_url_netloc(netloc: str) -> str:
    if "@" not in netloc:
        return netloc
    return "<redacted>@" + netloc.rsplit("@", 1)[1]


def _redact_url_path(host: str, path: str) -> str:
    segments = path.split("/")
    if "discord.com" in host or "discordapp.com" in host:
        return _redact_segments_after_prefix(segments, ["api", "webhooks"])
    if host == "hooks.slack.com":
        return _redact_segments_after_prefix(segments, ["services"])
    if host == "api.telegram.org":
        return "/".join(
            "bot<redacted>" if segment.startswith("bot") and len(segment) > 3 else segment
            for segment in segments
        )
    if host == "webhook.site":
        return _redact_segments_after_prefix(segments, [])
    if host == "pastebin.com":
        return _redact_segments_after_prefix(segments, ["raw"])
    if host == "gist.githubusercontent.com":
        return _redact_segments_after_prefix(segments, [])
    return path


def _redact_segments_after_prefix(segments: list[str], prefix: list[str]) -> str:
    redacted: list[str] = []
    prefix_index = 0
    for segment in segments:
        if segment == "":
            redacted.append(segment)
            continue
        if prefix_index < len(prefix) and segment == prefix[prefix_index]:
            redacted.append(segment)
            prefix_index += 1
            continue
        if prefix_index == len(prefix):
            redacted.append("<redacted>")
        else:
            redacted.append(segment)
    return "/".join(redacted)


def hash_sensitive_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
