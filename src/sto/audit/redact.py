"""Remove secrets before anything is stored (PLAN 4.9). Comment text is kept.

* A value under a key whose normalised name *ends in* a secret word is replaced whole, whatever
  the value is (so ``{"token": 5}`` becomes ``"[REDACTED]"``). The name is split at camel-case and
  separators, lower-cased and stripped of digits, and trailing filler such as ``old``, ``value``,
  ``header`` or ``pem`` is dropped, so ``APIToken``, ``AWSSecret``, ``sshKey``, ``password1``,
  ``password_old``, ``token_value``, ``auth_header``, ``private_key_pem`` and ``pass`` all match.
  ``tokens_used``, ``token_budget``, ``secret_ref``, ``token_hash``, a bare ``tokens`` (a count),
  ``oauth`` and ``foo_key`` are kept.
* Secret-shaped substrings of any string are replaced in place, with the same stem list as the key
  rule: provider tokens, JWTs (also glued to a word, or after ``%20`` and ``%3D``), private key
  blocks (an unterminated one is cut to the end), ``Authorization`` headers of any scheme, cookies,
  credentials in URLs, ``name=value`` / ``"name": "value"`` / ``name := value`` / ``name => value``
  pairs (with ``password1``, ``DB_PASSWORD_1`` style suffixes), ``--password x``,
  ``<password>x</password>``, and ``?sig=`` / ``X-Amz-Signature=`` in URLs. A string used as a
  dict key is redacted too, on the whole key.

Every step is linear in the input: no pattern has a nested or open-ended repeat that can back off
over the whole string, and colliding redacted keys get a counter instead of a search. The linearity
test is the guard for any change here. Redaction is idempotent on the shapes in the tests, which
is not a guarantee: ``https://u:ab/cd@X@h`` changes again on a second pass.

**Stays undetected, by design:**

* base64 or otherwise encoded secrets, zero-width or look-alike characters inside a token, and
  high-entropy strings with no name or prefix to give them away;
* a URL that is fully percent-encoded, scheme and credentials included
  (``https%3A%2F%2Fu%3Ap...``); ``password%3D...`` and ``token%3A...`` are caught;
* URL passwords of more than 300 characters, and passwords containing both ``/`` and ``@``;
* JSON escaped four or more levels deep;
* other query-string signatures (``session=``, ``sid=``) unless the name is a secret name, and
  space-separated command-line values other than ``--name value``;
* secrets after a word that is not a stem (``the key is ...``), and names in other languages.

Prose such as ``the token: looks wrong`` is redacted (``the token: [REDACTED] wrong``): a word
after ``token:`` is taken for a value.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

# --- names: one list, used for dict keys and for text ------------------------------------------

# Stems that name a secret. A dict key is a secret if its normalised name ends in one of these (or
# is one of the words below); the text patterns are built from the same list.
_STEMS = (
    "token", "secret", "password", "passwd", "passphrase", "pwd", "credential",
    "apikey", "accesskey", "privatekey", "secretkey", "signingkey", "encryptionkey", "sshkey",
)  # fmt: skip
_LAST_WORDS = frozenset(
    {
        "pass",
        "authorization",
        "cookie",
        "cookies",
        "auth",
        "jwt",
        "bearer",
        "secrets",
        "passwords",
        "credentials",
    }  # fmt: skip
)
# trailing words that do not change what a name holds: password_old, token_value, auth_header,
# private_key_pem. (token_hash is not here: a hash is not the secret.)
_FILLER = frozenset(
    {"old", "new", "value", "val", "current", "previous", "prev", "text", "str", "header", "pem"}
)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SPLIT = re.compile(r"[^A-Za-z]+")


def _is_secret_name(name: str) -> bool:
    words = [w.lower() for w in _SPLIT.split(_CAMEL.sub("_", name)) if w]
    while len(words) > 1 and words[-1] in _FILLER:
        words.pop()
    if not words:
        return False
    return words[-1] in _LAST_WORDS or "".join(words).endswith(_STEMS)


def _stem_pattern(stem: str) -> str:
    """A text pattern for a stem: ``apikey`` is also ``api key``, ``api_key`` and ``api-key``;
    a plural is allowed for the words that have one."""
    for tail in ("key",):
        if stem.endswith(tail) and stem != tail:
            return stem[: -len(tail)] + r"[ _-]?" + tail
    return stem + ("s?" if stem in {"secret", "password", "credential"} else "")


_NAMES = "|".join(_stem_pattern(s) for s in _STEMS)
# the same trailing words and numbers as in dict keys: password1, DB_PASSWORD_1, token_value
_SFX = r"(?:[_-]?\d+|[_-](?:old|new|value|val|current|previous|prev|text|str))*"

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
_Q = r"(?:\\*[\"'])?"  # an optional quote, possibly escaped any number of times (JSON in JSON)
_SEP = r"(?::=|=>|->|[=:]|%3[DdAa])(?:\s|%20)*"
_QUOTED = (
    r"\\+\"(?:[^\"\\]|\\(?!\"))*(?:\\+\")?"  # \"escaped\" (JSON inside a string)
    r"|\"(?:[^\"\\]|\\.)*\"?"  # "quoted", with escapes, or cut off
    r"|'(?:[^'\\]|\\.)*'?"
)
_VAL = _QUOTED + r"|(?!\[REDACTED\])[^\s&]{4,}"  # bare: up to whitespace or &
_REST = (
    _QUOTED + r"|(?!\s|%20)(?!\[REDACTED\])[^\r\n]+"
)  # a header value: quoted, or the rest of the line
_BEARER = re.compile(
    r"(\bbearer(?:\s|%20)+)(?:(?=[A-Za-z0-9._~+/=-]{0,200}\d)[A-Za-z0-9._~+/=-]{8,}"
    r"|[A-Za-z0-9._~+/=-]{20,})",
    re.I,
)
_AUTHZ = re.compile(
    r"((?<![A-Za-z])authorization" + _Q + r"\s*(?:[=:]|%3[Aa])(?:\s|%20)*)(?:" + _REST + r")",
    re.I,
)
_COOKIE = re.compile(
    r"((?<![A-Za-z])(?:set-)?cookies?" + _Q + r"\s*(?:[=:]|%3[DdAa])(?:\s|%20)*)(?:" + _REST + r")",
    re.I,
)
_AUTH_JWT = re.compile(
    r"((?<![A-Za-z])(?:auth|jwt)" + _Q + r"\s*" + _SEP + r"[\"']?)(?=[A-Za-z0-9._~+/=:-]{0,64}\d)"
    r"[A-Za-z0-9._~+/=:-]{12,}",
    re.I,
)
_URL_CREDS = re.compile(
    r"([a-z][a-z0-9+.-]{1,20}://)"  # no boundary before it: x_https:// and url_postgres:// count
    r"(?:[^\s/]{1,300}@|[^\s:/@]{0,200}:(?!\d{1,5}(?:/|\s|$))[^\s]{1,300}?@)",
    re.I,
)
_ASSIGN = re.compile(
    r"(" + _NAMES + r")" + _SFX + r"(?P<sep>" + _Q + r"\s*" + _SEP + r")(?:" + _VAL + r")",
    re.IGNORECASE,
)
_CLI = re.compile(  # --password x, --token x
    r"((?<![A-Za-z0-9-])--(?:" + _NAMES + r")" + _SFX + r"[ \t]+)(?!-)\S{4,}",
    re.IGNORECASE,
)
_XML = re.compile(  # <password>x</password>
    r"(<(?:" + _NAMES + r")" + _SFX + r">)[^<\r\n]{1,1000}(?=</)", re.IGNORECASE
)
_SIGNED_URL = re.compile(  # [?&]sig=..., X-Amz-Signature=...
    r"((?:[?&](?:sig|signature)|x-amz-signature)=)[^\s&]+", re.IGNORECASE
)
_PASS = re.compile(  # "pass" is a common word: only with = or as a quoted key
    r"((?<![A-Za-z])pass(?P<sep>" + _Q + r"\s*=\s*|\\*[\"']\s*:\s*))(?:" + _VAL + r")",
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
    text = _SIGNED_URL.sub(lambda m: m.group(1) + REDACTED, text)
    text = _CLI.sub(lambda m: m.group(1) + REDACTED, text)
    text = _XML.sub(lambda m: m.group(1) + REDACTED, text)
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
