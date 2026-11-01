"""Remove secrets before anything is stored (PLAN 4.9). Comment text is kept.

Two rules, both on the *stored* form: a value under a key that names a secret is replaced
whole, and token-shaped substrings of any string are replaced in place. The hash covers the
redacted form, so redaction can never be mistaken for tampering. Redaction is idempotent and
never changes keys or non-string values.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_SECRET_KEY = re.compile(
    r"(?:^|[_\-.])(?:token|secret|password|passwd|pwd|authorization|credential|credentials"
    r"|api[_\-]?key|private[_\-]?key|access[_\-]?key|client[_\-]?secret|cookie)s?(?:$|[_\-.])"
    r"|apikey|accesstoken|privatekey",
    re.IGNORECASE,
)

_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
_BEARER = re.compile(r"(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_ASSIGN = re.compile(
    r"(\b(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|client[_-]?secret)"
    r"\s*[=:]\s*)[^\s,;\"']{4,}",
    re.IGNORECASE,
)


def redact_text(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    return _ASSIGN.sub(lambda m: m.group(1) + REDACTED, text)


def redact(value: Any) -> Any:
    """A redacted copy of JSON-shaped data; the input is not modified."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            k: REDACTED if isinstance(k, str) and _SECRET_KEY.search(k) else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value
