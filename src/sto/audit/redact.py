"""Remove secrets before anything is stored (PLAN 4.9). Comment text is kept.

* A value under a key that *ends in* a secret word (``password``, ``DB_PASSWORD``, ``sessionToken``,
  ``api_key``, ``mySecret``) is replaced whole. ``tokens_used``, ``token_budget`` and ``secret_ref``
  name numbers and references, not secrets, and are kept.
* Token-shaped substrings of any string are replaced in place: provider tokens, JWTs, private key
  blocks (an unterminated one is cut to the end), ``Bearer``/``Basic`` credentials, credentials in
  URLs and ``name=value`` / ``"name": "value"`` pairs. A string used as a dict key is redacted too.

Every step is linear in the input: no pattern has a nested or open-ended repeat that can back off
over the whole string. Redaction is idempotent and does not change non-string values. Base64 or
zero-width-obfuscated secrets are not detected.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

_SECRET_WORDS = frozenset(
    {
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "authorization",
        "credential",
        "apikey",
        "cookie",
        "auth",
        "jwt",
        "bearer",
    }  # fmt: skip
)
_KEY_QUALIFIERS = frozenset({"api", "secret", "private", "access", "signing", "ssh", "encryption"})
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def _is_secret_name(name: str) -> bool:
    words = [w.lower() for w in _SPLIT.split(_CAMEL.sub("_", name)) if w]
    if not words:
        return False
    last = words[-1].removesuffix("s") if len(words[-1]) > 3 else words[-1]
    if last in _SECRET_WORDS:
        return True
    return last == "key" and len(words) > 1 and words[-2] in _KEY_QUALIFIERS


_TOKENS = (
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
)
_BEARER = re.compile(r"(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_URL_CREDS = re.compile(r"(\b[a-z][a-z0-9+.-]{1,20}://)[^\s/@:]{1,200}:[^\s/@]{1,200}@", re.I)
_ASSIGN = re.compile(
    r"(token|secret|password|passwd|passphrase|pwd|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|secret[_-]?key|credentials?)"
    r"(?P<sep>[\"']?\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;\"'&}]{4,})",
    re.IGNORECASE,
)
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]{0,40}PRIVATE KEY-----")


def _redact_pem(text: str) -> str:
    """Linear scan: a block runs from its header to its footer, or to the end without one."""
    out, pos = [], 0
    while (start := text.find("-----BEGIN ", pos)) != -1:
        header = _PEM_BEGIN.match(text, start)
        if header is None:
            out.append(text[pos : start + 11])
            pos = start + 11
            continue
        out.append(text[pos:start])
        out.append(REDACTED)
        end = _PEM_END.search(text, header.end())
        pos = len(text) if end is None else end.end()
    out.append(text[pos:])
    return "".join(out)


def redact_text(text: str) -> str:
    text = _redact_pem(text)
    for pattern in _TOKENS:
        text = pattern.sub(REDACTED, text)
    text = _BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _URL_CREDS.sub(lambda m: m.group(1) + REDACTED + "@", text)
    return _ASSIGN.sub(lambda m: m.group(1) + m.group("sep") + REDACTED, text)


def redact(value: Any) -> Any:
    """A redacted copy of JSON-shaped data; the input is not modified."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            new_v = REDACTED if isinstance(k, str) and _is_secret_name(k) else redact(v)
            new_k = redact_text(k) if isinstance(k, str) else k
            while new_k in out:  # two secrets as keys must not overwrite each other
                new_k = f"{new_k}#"
            out[new_k] = new_v
        return out
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value
