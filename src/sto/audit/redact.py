"""Remove secrets before anything is stored (PLAN 4.9). Comment text is kept.

* A value under a key whose normalised name *ends in* a secret word is replaced whole. The name is
  split at camel-case and separators, lower-cased and stripped of digits, and trailing filler such
  as ``old`` or ``value`` is dropped, so ``APIToken``, ``AWSSecret``, ``accesstoken``, ``sshKey``,
  ``password1``, ``password_old``, ``token_value`` and ``pass`` all match. ``tokens_used``,
  ``token_budget``, ``secret_ref`` and a bare ``tokens`` (a count) name numbers and references and
  are kept, as is ``foo_key``.
* Secret-shaped substrings of any string are replaced in place: provider tokens, JWTs (also when
  glued to a word, or after ``%20`` and ``%3D``), private key blocks (an unterminated one is cut
  to the end), ``Authorization`` headers of any scheme, cookies, credentials in URLs, and
  ``name=value`` / ``"name": "value"`` pairs. A string used as a dict key is redacted too, on the
  whole key.

Every step is linear in the input: no pattern has a nested or open-ended repeat that can back off
over the whole string, and colliding redacted keys get a counter instead of a search. Redaction is
idempotent and does not change non-string values.

**Stays undetected, by design:** base64 or otherwise encoded secrets, zero-width or look-alike
characters inside a token, high-entropy strings with no name or prefix to give them away,
signatures in query strings (``sig=``, ``X-Amz-Signature=``, ``session=``) unless the name is a
secret name, and percent-encoded URL credentials. Prose such as ``the token: looks wrong`` is
redacted (``the token: [REDACTED] wrong``): a word after ``token:`` is taken for a value.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

# --- names ------------------------------------------------------------------------------------

_LAST_WORDS = frozenset(
    {
        "pass",
        "passwd",
        "pwd",
        "passphrase",
        "authorization",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "auth",
        "jwt",
        "bearer",
        "secrets",
        "passwords",
    }  # fmt: skip
)
_SUFFIXES = (
    "token", "secret", "password", "apikey", "accesskey", "privatekey", "secretkey",
    "signingkey", "sshkey", "encryptionkey", "credential",
)  # fmt: skip
_FILLER = frozenset({"old", "new", "value", "val", "current", "previous", "prev", "text", "str"})
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SPLIT = re.compile(r"[^A-Za-z]+")


def _is_secret_name(name: str) -> bool:
    words = [w.lower() for w in _SPLIT.split(_CAMEL.sub("_", name)) if w]
    while len(words) > 1 and words[-1] in _FILLER:
        words.pop()
    if not words:
        return False
    return words[-1] in _LAST_WORDS or "".join(words).endswith(_SUFFIXES)


# --- text -------------------------------------------------------------------------------------

_TOKENS = (
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"xapp-[A-Za-z0-9-]{10,}"),
    # a JWT segment cannot contain another "eyJ", so a start is never retried inside a long run
    re.compile(r"eyJ(?:(?!eyJ)[A-Za-z0-9_-]){5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    re.compile(r"npm_[A-Za-z0-9]{36}"),
    re.compile(r"hf_[A-Za-z0-9]{30,}"),
    re.compile(r"pypi-AgE[A-Za-z0-9_-]{20,}"),
)
_SEP = r"(?:[=:]|%3[DdAa])(?:\s|%20)*"
_VAL = (
    r"\\\"(?:[^\"\\]|\\(?!\"))*(?:\\\")?"  # \"escaped\" (JSON inside a string)
    r"|\"(?:[^\"\\]|\\.)*\"?"  # "quoted", with escapes, or cut off
    r"|'(?:[^'\\]|\\.)*'?"
    r"|[^\s&]{4,}"  # bare: up to whitespace or &
)
_BEARER = re.compile(
    r"(\bbearer(?:\s|%20)+)(?:(?=[A-Za-z0-9._~+/=-]{0,200}\d)[A-Za-z0-9._~+/=-]{8,}"
    r"|[A-Za-z0-9._~+/=-]{20,})",
    re.I,
)
_AUTHZ = re.compile(
    r"(\bauthorization(?:\\?[\"'])?\s*"
    + r"(?:[=:]|%3[Aa])(?:\s|%20)*(?:\\?[\"'])?)[^\r\n\"'&]{3,}",
    re.I,
)
_COOKIE = re.compile(
    r"(\b(?:set-)?cookie(?:\\?[\"'])?\s*"
    + r"(?:[=:]|%3[DdAa])(?:\s|%20)*(?:\\?[\"'])?)[^\r\n\"'&]+",
    re.I,
)
_AUTH_JWT = re.compile(
    r"(\b(?:auth|jwt)[\"']?\s*" + _SEP + r"[\"']?)(?=[A-Za-z0-9._~+/=-]{0,64}\d)"
    r"[A-Za-z0-9._~+/=-]{12,}",
    re.I,
)
_URL_CREDS = re.compile(
    r"(\b[a-z][a-z0-9+.-]{1,20}://)"
    r"(?:[^\s/]{1,200}@|[^\s:/@]{0,200}:(?!\d{1,5}(?:/|\s|$))[^\s]{1,200}?@)",
    re.I,
)
_ASSIGN = re.compile(
    r"(token|secrets?|passwords?|passwd|passphrase|pwd|api[ _-]?key|access[_-]?key"
    r"|private[_-]?key|secret[_-]?key|credentials?)"
    r"(?P<sep>(?:\\?[\"'])?\s*" + _SEP + r")(?:" + _VAL + r")",
    re.IGNORECASE,
)
_PASS = re.compile(  # "pass" is a common word: only with = or as a quoted key
    r"((?<![A-Za-z])pass(?P<sep>(?:\\?[\"'])?\s*=\s*|\\?[\"']\s*:\s*))(?:" + _VAL + r")",
    re.IGNORECASE,
)
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = re.compile(r"-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----")


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
    text = _AUTHZ.sub(lambda m: m.group(1) + REDACTED, text)
    text = _BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _COOKIE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _AUTH_JWT.sub(lambda m: m.group(1) + REDACTED, text)
    text = _URL_CREDS.sub(lambda m: m.group(1) + REDACTED + "@", text)
    text = _PASS.sub(lambda m: m.group(1) + REDACTED, text)
    return _ASSIGN.sub(lambda m: m.group(1) + m.group("sep") + REDACTED, text)


def redact(value: Any) -> Any:
    """A redacted copy of JSON-shaped data; the input is not modified."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        seen: dict[Any, int] = {}  # how many keys already collided onto each redacted key
        for k, v in value.items():
            new_v = REDACTED if isinstance(k, str) and _is_secret_name(k) else redact(v)
            new_k = redact_text(k) if isinstance(k, str) else k
            if new_k in out:  # two secrets as keys must not overwrite each other
                seen[new_k] = seen.get(new_k, 0) + 1
                new_k = f"{new_k}#{seen[new_k]}"
                while new_k in out:
                    seen[new_k] = seen.get(new_k, 0) + 1
                    new_k = f"{new_k}#{seen[new_k]}"
            out[new_k] = new_v
        return out
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value
