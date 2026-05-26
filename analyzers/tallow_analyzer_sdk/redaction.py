"""Evidence excerpt redaction helpers."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

MAX_EXCERPT_LEN = 240

_TOKEN_PATTERN = re.compile(
    r'(?i)(token|secret|password|api[_-]?key)\s*=\s*"([^"]{8,})"'
)
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-+/=]{8,})")
_URL_QUERY_PATTERN = re.compile(r"(\?)([^#\s]+)")


def _redaction_tag(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"<redacted:sha256:{digest}>"


def redact_text(text: str, *, max_len: int = MAX_EXCERPT_LEN) -> tuple[str, bool]:
    redacted = False
    output = text

    def token_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return f'{match.group(1)}="{_redaction_tag(match.group(2))}"'

    output = _TOKEN_PATTERN.sub(token_repl, output)
    output = _BEARER_PATTERN.sub(lambda m: f"{m.group(1)}{_redaction_tag(m.group(2))}", output)

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
    if not parts.query:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "<redacted>", parts.fragment))


def hash_sensitive_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
