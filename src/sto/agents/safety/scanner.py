"""Secret scanner (D5-04, threat T4).

``scan`` finds secrets by known format, by a secret-looking name on a *literal* assignment, and by
entropy, so a canary with an unusual name or inside source code is still caught. ``screen`` also
redacts.

Seam with prompt rendering (D5-03, ``sto.agents.prompts.render``). Scan the *raw* text first, then
redact, then hand the result to ``Untrusted(...)``, which neutralises frame tags and hashes. The
prompt hash is therefore taken after redaction and never depends on a secret::

    clean = screen(raw).text
    render(tpl, ticket=Untrusted(clean, "ticket"))

Rules that hold everywhere in this package:

* Fail closed. Any error, bad input, oversize input or exceeded deadline raises ``ScanError``.
  Nothing returns "no findings" because a scan could not finish.
* Deterministic. Input over ``MAX_SCAN_CHARS`` is refused up front. ``DEADLINE_SECONDS`` is only a
  generous backstop (about ten times the worst measured time), so the same input gives the same
  answer on a slow or busy machine.
* Nothing returns or logs the scanned text. ``Finding`` holds a kind (offsets are hidden from
  ``repr``) and error messages never quote input.
* Every regex runs in linear time on hostile input. Each one either starts on a fixed literal, or
  starts only at the beginning of a run (a lookbehind on the run's own character class), and all
  other repeats are bounded. A regex cannot be interrupted, which is why linearity matters and is
  pinned by a test.

Rule precedence when spans overlap: format rules, then secret-named assignments, then entropy.
Format rules apply everywhere and always block. The two heuristics (assignment and entropy) are
tuned not to fire on code expressions, paths, slugs or hashes.

Allowances (placeholders, versions, expressions, public hashes) always ``fullmatch`` the whole value
against a tight shape. None is a prefix, substring or ``match`` test, and none depends on a file
path: a path exemption would be a smuggling route.

Known limits, by design (each one is pinned by ``test_every_stated_limit_is_pinned``):

* Entropy (threat T4, "unusual names"). A random value under a name with no secret word is judged
  by length, character classes and entropy, and short ones are missed. Measured over 2000 random
  values: base62 24 characters 14% missed, 32 characters 2.5%, 40 characters 0.7%; lower-case
  letters and digits 24 characters 42%; upper-case base32 24 characters 60%, 32 characters 9.8%;
  letters only below 40 characters always. Canaries for T4 must therefore be 40 or more characters,
  or in a known format (every ``_FORMATS`` rule matches at any length). The rule is not tightened:
  it would flag identifiers, hashes and slugs in code.
* Characters: full-width (compatibility) and zero-width characters are not folded. URL-encoded
  pieces, a secret split over lines or by string concatenation, and JSON character arrays are
  not joined. Hex-encoded tokens of non-hash lengths and base64 of a password (or of a key with
  no known format) are not decoded; hex and base64 of a known token format are.
* Prose and shell forms: ``the password is hunter2``, ``curl -u user:pw``, ``--password x``,
  ``-pSECRET``, ``?key=`` and ``?sig=`` query values, a ``Cookie:`` header, XML attribute pairs
  (``<add key="password" value="x"/>``), and short-line PEM bodies without their header. A
  ``getenv``/``get``/``setdefault``/``setenv``/``putenv`` call with a secret name and a literal
  default is caught.
* Calls that carry a literal without a name next to it: ``Field(default="x")``, ``SecretStr("x")``,
  ``process.env.X || "x"``; and ``var password string = "x"`` (Go).
* Reach: a secret name is read up to 32 characters past its keyword (``password`` plus 33
  characters of suffix before the ``=`` is not read). ``password=pa"ssw0rd12`` (a quote inside an
  unquoted value) and ``password: abc::def`` are not read.
* ``password:`` and ``NAME=`` forms. Unquoted after ``:`` (YAML), a lower-case word
  (``password: correcthorse``), a CamelCase phrase (``password: CorrectHorseBatteryStaple``) and a
  snake phrase (``password: Correct_Horse_Staple``) are read as types and names, not secrets. A
  bare ``$ecret99``, a backticked bare value, and the numeric literal ``password = 12345678`` pass.
  A lower-case slug (``my-api-key``) is a secret under every name except ``token`` and ``auth``,
  where it is a CSS class or a storage key (``.token:focus-within``, ``TOKEN_KEY = "x_y"``).
* A bare 40-hex value is indistinguishable from a git SHA. A quoted hex of 32+ under a name with
  no sha, commit, hash, digest, etag or checksum segment is flagged, and a name that ends in a
  credential word (``HMAC_SHA256_KEY``) is always a credential.
* Embedded base64 images (``data:image/png;base64,...``) are high entropy and are flagged.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic as _now

from sto.domain.errors import PermanentError

MAX_SCAN_CHARS = 1_000_000
DEADLINE_SECONDS = 60.0
ENTROPY_MIN_LENGTH = 24
ENTROPY_THRESHOLD = 4.0  # bits per char. Hex tops out at 4.0, so hashes and UUIDs never reach it.
MIN_UPPER_RATIO = 0.25  # random base64 is about 40% upper; camelCase identifiers are far lower


class ScanError(PermanentError):
    """The scan could not complete. The step blocks; the text is never passed on unscanned."""


@dataclass(frozen=True)
class Finding:
    """A kind, and where. Offsets are for redaction only and are kept out of ``repr``."""

    kind: str
    start: int = field(repr=False)
    end: int = field(repr=False)


@dataclass(frozen=True)
class Screened:
    """Redacted text and what was found. ``text`` is hidden from ``repr``."""

    text: str = field(repr=False)
    findings: tuple[Finding, ...]


Span = tuple[str, int, int]

# --- format rules ------------------------------------------------------------------------------
# Distinctive prefixes need no leading boundary, so `KEY_AKIA..`, `x-ghp_..`, `%3DAKIA..` and a
# literal `\nAKIA..` are all caught. Where the prefix is short or common (AIza, sk-), a boundary
# stays so base64 blobs and words do not match.
_NB = r"(?<![A-Za-z0-9])"
_RUN = r"(?<![A-Za-z0-9_])"
_FORMATS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "aws",
        re.compile(
            r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ABIA|ACCA|APKA|ASCA)[A-Z2-7]{16}(?![A-Z0-9])"
        ),
    ),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,255}")),
    ("github", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}")),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,255}")),
    ("slack", re.compile(r"xox[abeprs]-[A-Za-z0-9-]{10,200}")),
    ("slack", re.compile(r"xapp-[0-9]-[A-Za-z0-9-]{10,200}")),
    (
        "slack",
        re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"),
    ),
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,200}")),
    ("openai", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,200}")),
    ("openai", re.compile(rf"{_NB}sk-[A-Za-z0-9]{{48}}(?![A-Za-z0-9])")),
    ("stripe", re.compile(r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,100}")),
    ("stripe", re.compile(r"whsec_[A-Za-z0-9]{16,100}")),
    ("digitalocean", re.compile(r"do[por]_v1_[0-9a-f]{64}")),
    ("twilio", re.compile(rf"{_NB}SK[0-9a-f]{{32}}(?![0-9A-Za-z])")),
    ("google", re.compile(rf"{_RUN}AIza[A-Za-z0-9_-]{{35}}(?![A-Za-z0-9_-])")),
    (
        "jwt",
        re.compile(
            rf"{_RUN}eyJ[A-Za-z0-9_-]{{5,256}}\.eyJ[A-Za-z0-9_-]{{5,1024}}\.[A-Za-z0-9_-]{{5,1024}}"
        ),
    ),
    # A real bearer token has a digit. `Bearer authenticationMiddlewareLayer` is prose or code.
    (
        "bearer",
        re.compile(
            r"(?i)(?<![A-Za-z])bearer[ \t]{1,8}(?=[A-Za-z0-9._~+/=-]{0,2047}[0-9])"
            r"[A-Za-z0-9._~+/-]{16,2048}=*"
        ),
    ),
)
_KEY_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_KEY_END = "-----END "
_SCHEME = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,20}://")
_URL_STOP = re.compile(r"[\s\"'>`]")
_URL_WINDOW = 400
_USER_ONLY_SCHEMES = frozenset({"ssh", "sftp", "scp", "rsync", "git+ssh", "ssh+git", "svn+ssh"})


def _known_spans(text: str) -> list[Span]:
    spans: list[Span] = []
    for kind, pattern in _FORMATS:
        spans.extend((kind, m.start(), m.end()) for m in pattern.finditer(text))
    pos = 0
    while True:
        header = _KEY_HEADER.search(text, pos)
        if header is None:
            break
        end_at = text.find(_KEY_END, header.end())
        if end_at < 0:
            spans.append(("private_key", header.start(), len(text)))
            break
        close = text.find("-----", end_at + len(_KEY_END))
        end = len(text) if close < 0 else close + 5
        spans.append(("private_key", header.start(), end))
        pos = end
    spans.extend(_url_credential_spans(text))
    return spans


# --- allowances: each one a whole-value shape ----------------------------------------------------
_PLACEHOLDER = re.compile(
    r"""
      \$\{[^}\n]*\}                  # ${VAR}
    | \$\([^\n]*\)                   # $(cmd)
    | \$[A-Z_][A-Z0-9_]*             # $VAR, upper case only: `$ecret99` is a password
    | <[^<>\n]*>                     # <your-password>
    | \{\{[^{}\n]*\}\}               # {{ template }}
    | \{[A-Za-z_][\w.]*\}            # {name}, {settings.password}
    | %\([A-Za-z_]\w*\)[sd] | %[sd]  # %(name)s
    | \[REDACTED(?::[a-z_]+)?\]       # our own placeholder
    | \*{3,} | [xX]{3,}              # ****, xxxxxxxx
    | [A-Za-z]{1,4}[-_][A-Za-z0-9_-]{0,10}\.\.\. | \.\.\.   # sk-ant-...  (an elision)
    | (?i:(?:test|fake|mock|dummy|example)(?:[-_](?:token|key|secret|password))?)
    | (?i:your[-_]?(?:password|token|secret|api[-_]?key|key)(?:[-_]here)?)
    """,
    re.VERBOSE,
)
# Words that are never a credential when they stand alone as a bare value (code and types).
_BARE_WORDS = frozenset(
    {
        "changeme", "change-me", "change_me", "redacted", "placeholder", "secret", "password",
        "token", "null", "none", "nil", "true", "false", "undefined", "required", "optional",
        "string", "str", "bytes", "int", "integer", "bool", "boolean", "float", "number", "object",
        "dict", "list", "any", "unknown", "never", "void", "todo", "tbd", "empty", "unset",
        "inherit", "include", "omit", "same-origin", "return", "continue", "break", "pass",
        "raise", "yield", "await", "async", "def", "class", "lambda", "not", "and", "or", "if",
        "else", "elif", "for", "while", "try", "except", "finally", "with", "import", "from", "as",
        "global", "nonlocal", "del", "assert", "const", "let", "var", "function", "new", "this",
        "typeof", "throw", "switch", "case", "default", "export", "static", "public", "private",
    }
)  # fmt: skip
# Quoted and URL values get only the words that mean "no value here".
_QUOTED_WORDS = frozenset(
    {
        "changeme", "change-me", "change_me", "redacted", "placeholder", "todo", "tbd", "unset",
        "include", "omit", "same-origin",
    }
)  # fmt: skip
# Test literals, whole: the closed vocabulary of the repo's own auth tests.
_TEST_VOCAB = re.compile(
    r"(?i)(?:wrong|bad|invalid|expired|other|good|nope)(?:[-_ ](?:token|key|secret|password))?"
)
_TEST_SCHEME = re.compile(
    r"(?i)(?:bearer|basic|token)[ \t]+(?:test|fake|mock|dummy|example"
    r"|wrong|bad|invalid|expired|other|good|nope)"
    r"(?:[-_](?:token|key|secret|password))?"
)
_SCHEME_TOKEN = re.compile(r"(?i)(?:bearer|basic|token|digest|negotiate)[ \t]+(\S+)")
_NUMBER = re.compile(r"[-+]?(?:0[xXbBoO][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][-+]?\d+)?)")
MAX_NUMBER_CHARS = 20
# A version under a package-style key: `"js-tokens": "^4.0.0"`. Dotted core or a range operator.
_VERSION = re.compile(
    r"(?:[\^~]|[<>]=?|=)?\d+(?:\.(?:\d+|x|\*)){1,3}(?:-(?:rc|alpha|beta|dev|pre)\.?\d*)?"
)
_PACKAGE_KEY = re.compile(r"@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?")
# SigV4 scope: key id / date / region / service / aws4_request, and nothing else.
_SIGV4_SCOPE = re.compile(
    r"(?:[A-Z0-9]{16,128}|(?i:test|fake|mock|dummy|example))/\d{8}/[a-z0-9-]+/[a-z0-9-]+/aws4_request"
)
_SCHEME_WORD = re.compile(r"(?i)(?:bearer|basic|token|digest)[ \t]*")
_SHELL_VAR = re.compile(r"\$[A-Za-z_]\w*")
_KEBAB = re.compile(r"[a-z]+(?:-[a-z]+)+")
_SLUG = re.compile(r"[a-z]+(?:[-_][a-z]+)+")
_SLUG_KW = frozenset({"token", "auth"})  # only these names may hold a lowercase slug
_CPP_PATH = re.compile(r"[A-Za-z_]+(?:::[A-Za-z_]+)+")
_FS_PATH = re.compile(r"[~/.][\w./~-]*")
_ARN_BEFORE = re.compile(r"arn:aws[a-z-]*:[^\s\"']*$")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ATOM = re.compile(r"[A-Za-z_]\w*")
_CLOSER = re.compile(r"[)\]}]")
_GENERIC = re.compile(r"[A-Za-z_][\w.,]*")
_PASSWORD_KW = frozenset({"password", "passwd", "passphrase"})
_INTERPOLATION = re.compile(r"\$?\{[^{}]*\}")


def _is_placeholder(value: str) -> bool:
    """A placeholder in a quoted or URL value."""
    return _PLACEHOLDER.fullmatch(value) is not None or value.lower() in _QUOTED_WORDS


def _is_bare_placeholder(value: str) -> bool:
    return _PLACEHOLDER.fullmatch(value) is not None or value.lower() in _BARE_WORDS


def _norm(text: str) -> str:
    return "".join(c for c in text.lower() if c.isalnum())


def _is_expression(
    value: str, *, allow_unfinished: bool, strict: bool, strict_index: bool = True
) -> bool:
    """Whole value is dotted names with calls and indexes.

    ``get_token()`` is; ``p(ss)w0rd1`` and ``s3cr3t[1]2`` are not, because something follows the
    closing bracket that no expression grammar allows. A call left open at a quote or a space
    (``os.environ[``) counts only where ``allow_unfinished`` says the rest is on another token.
    In ``strict`` mode (``NAME=value``) a bare dotted chain whose names hold digits is a literal
    (``Spring2024.Prod``), and so is a call or index with something inside the brackets
    (``P(ssw0rd1)``): only ``()`` and ``[]`` pass.
    """
    i, n = 0, len(value)
    called = False
    atoms: list[str] = []
    while i < n:
        atom = _ATOM.match(value, i)
        if atom is None:
            return False
        atoms.append(atom.group())
        i = atom.end()
        if i < n and value[i] == "<":  # Foo<Bar>(...)
            close = value.find(">", i)
            if close < 0:
                return allow_unfinished and _GENERIC.fullmatch(value[i + 1 :]) is not None
            if _GENERIC.fullmatch(value[i + 1 : close]) is None:
                return False
            i = close + 1
        while i < n and value[i] in "([":
            called = True
            if _CLOSER.search(value, i) is None:
                return allow_unfinished  # nothing closes it: unfinished (and a fast path)
            depth = 0
            group_start = i
            while i < n:
                if value[i] in "([{":
                    depth += 1
                elif value[i] in ")]}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            if depth > 0:
                return allow_unfinished  # unfinished: the rest is on another token
            if strict and i - group_start > 1 and (strict_index or value[group_start] == "("):
                return False
            i += 1
        if i < n and value[i] == ".":
            i += 1
            continue
        if i != n:
            return False
        return called or not (
            strict and len(atoms) > 1 and any(c.isdigit() for a in atoms for c in a)
        )
    return False


def _cut_at_unbalanced_closer(value: str) -> str:
    if _CLOSER.search(value) is None:
        return value
    depth = 0
    for i, c in enumerate(value):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return value[:i]
            depth -= 1
    return value


# --- URL credentials ---------------------------------------------------------------------------
_HOST_END = re.compile(r"[/:?#]")


def _is_local_host(rest: str) -> bool:
    """``localhost``, ``127.0.0.1`` or a dotless name such as ``db``: a dev database."""
    end = _HOST_END.search(rest)
    host = (rest if end is None else rest[: end.start()]).lower()
    return host in ("localhost", "127.0.0.1") or "." not in host


def _url_credential_spans(text: str) -> list[Span]:
    """``scheme://user:pw@host``, ``scheme://:pw@host`` and ``scheme://TOKEN@host``.

    The password may hold ``@`` (the last one before the path ends the userinfo) or ``/`` (a
    non-numeric "port" is not a port, so the last ``@`` is taken). A numeric, ``$`` or ``{`` port
    is not a password, and a bare user name before ``ssh://`` or ``sftp://`` is not a credential.
    """
    spans: list[Span] = []
    for m in _SCHEME.finditer(text):
        a = m.end()
        window = text[a : a + _URL_WINDOW]
        stop = _URL_STOP.search(window)
        run = window[: stop.start()] if stop else window
        cut = _URL_PATH.search(run)
        head = run if cut is None else run[: cut.start()]
        at = head.rfind("@")
        if at < 0 and cut is not None and ":" in head:
            port = head.split(":", 1)[1]
            last = run.rfind("@")
            if last > cut.start() and not (
                (port.isdigit() and len(port) <= 5) or port.startswith(("$", "{"))
            ):
                at = last
        if at < 0:
            continue
        userinfo = run[:at]
        if _PLACEHOLDER.fullmatch(userinfo):
            continue
        if ":" in userinfo:
            user, password = userinfo.split(":", 1)
            if not password or _is_placeholder(password):
                continue
            if _norm(password) == _norm(user) and _is_local_host(run[at + 1 :]):
                continue  # postgres:postgres@localhost
        else:
            scheme = text[m.start() : a - 3].lower()
            if (
                scheme in _USER_ONLY_SCHEMES
                or len(userinfo) < 8
                or _is_placeholder(userinfo)
                or (userinfo.isalpha() and userinfo.islower())
            ):
                continue
        spans.append(("url_credentials", a, a + at))
    return spans


# --- secret-named assignment -------------------------------------------------------------------
_NAME = re.compile(
    r"(?ix)"
    r"(?P<kw>password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key"
    r"|access[_-]?key|(?:signing|encryption|session|master)[_-]?key|credentials?|authorization"
    r"|(?<![A-Za-z0-9])(?:pass|pwd|auth)(?![A-Za-z0-9]))"
    r"[A-Za-z0-9_.-]{0,32}"
    r"(?:\\?[\"'])?\]?"
    r"[ \t]{0,20}"
    r"(?P<sep>:=|=>|[:=])"
    r"[ \t]{0,20}"
)
_NAME_KW = re.compile(
    r"(?i)password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key"
    r"|access[_-]?key|credentials?|authorization"
)
_BARE = re.compile(r"[^\s\"'`]{1,128}")
_AFTER_SCHEME = re.compile(r"[ \t]+([^\s\"'`]{1,128})")
_ESC_CUT = re.compile(r"\\[nrt]")  # a literal `\r\n` inside a source string
_NEXT_KEY = re.compile(r",(?=[A-Za-z_\"']\w*[:=])")
_STR_PREFIX = re.compile(r"(?i)(?:[rbfu]{1,2}|@)(?=[\"'`])")
_TYPED_TAIL = re.compile(r"(?:[ \t]*\|[ \t]*[\w.\[\]]+)*[ \t]*=[ \t]*")
_SEGMENTS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_AUTH_SCHEMES = frozenset({"basic", "bearer", "token", "digest", "negotiate"})
_URL_PATH = re.compile(r"[/?#]")
# `tokens_used`, `secret_name`, `password_label`: facts about a secret, not the secret. `id` is
# not here: `secret_id` is a credential (Vault AppRole).
_STRUCTURAL_SUFFIXES = frozenset(
    {
        "count", "counts", "used", "usage", "limit", "limits", "max", "min", "len", "length",
        "size", "type", "types", "name", "names", "url", "uri", "field", "fields", "header",
        "headers", "path", "file", "files", "dir", "arn", "ttl", "expiry", "expires",
        "endpoint", "param", "params", "prefix", "suffix", "env", "var", "vars", "ref", "kind",
        "mode", "provider", "digest", "hash", "sha", "checksum", "fingerprint", "method",
        "encoding", "tokenizer", "tokenizers",
    }
)  # fmt: skip
# Free-text suffixes: exempt only when the value reads as prose or a lowercase slug.
_FREE_SUFFIXES = frozenset(
    {
        "label", "help", "prompt", "description", "error", "message", "text", "hint", "title",
        "placeholder", "format", "scheme",
    }
)  # fmt: skip


def _segments(name: str) -> list[str]:
    return [s.lower() for s in _SEGMENTS.findall(name)]


def _bare_is_secret(
    value: str, *, env_style: bool, kwarg: bool, kw: str, unfinished_ok: bool, colon: bool = False
) -> bool:
    """Is an unquoted value after a secret name a literal? Allowances match the whole value."""
    if len(value) < 6 or _is_bare_placeholder(value):
        return False
    if len(value) <= MAX_NUMBER_CHARS and _NUMBER.fullmatch(value):
        return False
    if _SHELL_VAR.fullmatch(value) or _SIGV4_SCOPE.fullmatch(value):
        return False  # `?token=$token`: an expansion, where a quoted "$ecret99" is a password
    if kw in _SLUG_KW and _KEBAB.fullmatch(value):
        return False  # `.token:focus-within`; any other name may hold a passphrase
    if _CPP_PATH.fullmatch(value) or (kw == "pwd" and _FS_PATH.fullmatch(value)):
        return False
    core = value.rstrip("?")
    # `NAME=value` is strict; so is `password: value` (a type may be indexed, not called or dotted)
    strict = (env_style or (colon and kw in _PASSWORD_KW)) and not kwarg
    if _is_expression(
        core, allow_unfinished=unfinished_ok, strict=strict, strict_index=not colon or env_style
    ):
        if _IDENT.fullmatch(core) is None:
            return False  # dotted name, call or index
        has_digit = any(c.isdigit() for c in core)
        literal_context = env_style and not kwarg and kw not in ("pass", "auth")
        if "_" in core:
            return literal_context and has_digit  # snake_case names; `password=my_secret_2024`
        if has_digit:
            return True  # hunter2, Abc12345xyz
        return literal_context  # `NAME=word` is a literal; `x = word` and `x: Type` are not
    return True  # punctuation that is not an expression: a literal (`ab;cd1`, `pa$$w0rd`)


def _quoted_is_secret(
    value: str, *, name: str, kw: str, package_key: bool, upper_const: bool
) -> bool:
    v = value.strip()
    if len(v) < 4 or _is_placeholder(v) or _SIGV4_SCOPE.fullmatch(v):
        return False
    if _SCHEME_WORD.fullmatch(v):
        return False  # `"Bearer " + token`
    if _TEST_VOCAB.fullmatch(v) or _TEST_SCHEME.fullmatch(v):
        return False
    if _norm(v) == _norm(name.rsplit(".", 1)[-1]):
        return False  # WRONG_SECRET = "wrong_secret"
    if package_key and _VERSION.fullmatch(v):
        return False
    if kw == "auth" and v.isalpha():
        return False  # auth: "cognito"
    if kw in ("pwd", "auth") and _FS_PATH.fullmatch(v):
        return False  # pwd = "/tmp/x", auth: "/login"
    return not (upper_const and kw in _SLUG_KW and _SLUG.fullmatch(v))  # TOKEN_KEY = "x_y"


def _name_start(text: str, at: int) -> int:
    i = at
    low = max(0, at - 40)
    while i > low and (text[i - 1].isalnum() or text[i - 1] in "_.-"):
        i -= 1
    return i


def _find_close(text: str, quote: str, start: int, end: int) -> int:
    pos = start
    while True:
        i = text.find(quote, pos, end)
        if i < 0:
            return -1
        if len(quote) == 2:  # `\"` as written inside a JSON string
            return i
        backslashes = 0
        j = i - 1
        while j >= start and text[j] == "\\":
            backslashes += 1
            j -= 1
        if backslashes % 2 == 0:
            return i
        pos = i + 1


def _string_at(text: str, pos: int, spaced_after: bool) -> tuple[int, int, int, bool] | None:
    """A string literal at ``pos`` (after an optional prefix): (start, close, resume, template).

    A single-quoted string ends at a newline; only triple quotes span lines. An unterminated one
    runs to the end of the line (or the 2048-character window).
    """
    n = len(text)
    prefix = _STR_PREFIX.match(text, pos)
    p = prefix.end() if prefix else pos
    if p >= n:
        return None
    first = text[p]
    if text.startswith(('\\"', "\\'"), p):
        quote = text[p : p + 2]
    elif first in "\"'":
        quote = first * 3 if text.startswith(first * 3, p) else first
    elif first == "`" and spaced_after:
        quote = "`"
    else:
        return None
    start = p + len(quote)
    end = min(n, start + 2049)
    if len(quote) != 3:
        newline = text.find("\n", start, end)
        if newline >= 0:
            end = newline
    close = _find_close(text, quote, start, end)
    resume = close + len(quote) if close >= 0 else end
    if close < 0:
        close = end
    template = "{" in text[start:close] and (
        quote == "`" or (prefix is not None and prefix.group().lower().endswith("f"))
    )
    return start, close, resume, template


def _is_template(content: str) -> bool:
    """An f-string or template literal with no literal text of its own (4+ characters)."""
    rest = _INTERPOLATION.sub("", content).strip()
    return len(rest) < 4 or _SCHEME_WORD.fullmatch(rest) is not None


def _assignment_spans(text: str) -> list[Span]:
    spans: list[Span] = []
    n = len(text)
    resume = 0  # a quoted value already read is not scanned again for keywords
    for m in _NAME.finditer(text):
        if m.start() < resume:
            continue
        ns = _name_start(text, m.start())
        sep_s = m.start("sep")
        sep = m.group("sep")
        raw_name = text[ns:sep_s]
        name = raw_name.strip("\"'\\] \t")
        segs = _segments(name)
        last = segs[-1] if segs else ""
        kw = m.group("kw").lower()
        if sep == ":" and _ARN_BEFORE.search(text[max(0, ns - 160) : ns]):
            continue
        pos = m.end()
        if sep == ":" and pos < n and text[pos] == ":":
            continue  # `AWS::SecretsManager::Secret`
        if text.startswith("(", pos):
            pos += 1
        if pos >= n:
            continue
        key_quote = text[sep_s - 1 : sep_s]
        package_key = False
        if key_quote in ('"', "'") and sep_s > 1:
            opened = text.rfind(key_quote, max(0, sep_s - 120), sep_s - 1)
            package_key = opened >= 0 and bool(_PACKAGE_KEY.fullmatch(text[opened + 1 : sep_s - 1]))
        spaced_after = m.end() > m.end("sep")
        literal = _string_at(text, pos, spaced_after)
        if literal is not None:
            start, close, after, template = literal
            content = text[start:close]
            if last in _STRUCTURAL_SUFFIXES:
                # skipped values are still scanned for keywords: `token_url = ".../?secret=x"`
                scheme = _SCHEME_TOKEN.fullmatch(content.strip())
                if scheme and len(scheme.group(1)) >= 6 and not _is_placeholder(scheme.group(1)):
                    spans.append(("secret_assignment", start, close))
                    resume = after
                continue
            if last in _FREE_SUFFIXES and (
                any(c.isspace() for c in content) or _SLUG.fullmatch(content)
            ):
                continue
            resume = after
            if template and _is_template(content):
                continue
            if _quoted_is_secret(
                content,
                name=name,
                kw=kw,
                package_key=package_key,
                upper_const=not any(c.islower() for c in name),
            ):
                spans.append(("secret_assignment", start, close))
            continue
        if last in _STRUCTURAL_SUFFIXES:
            continue
        bare = _BARE.match(text, pos)
        if bare is None:
            continue
        run = _ESC_CUT.split(_NEXT_KEY.split(bare.group(), 1)[0], 1)[0]
        uncut = len(run)
        run = _cut_at_unbalanced_closer(run)
        closed_by_caller = len(run) < uncut  # `f(token=digest)`: the `)` is the caller's
        start, end = pos, pos + len(run)
        value = run.rstrip(",;")
        # No skip past a bare value: a keyword inside a call (`login(password="x")`) is scanned.
        # The work per match is bounded by the 128-character run.
        if value.lower() in _AUTH_SCHEMES and not run.endswith((",", ";")):
            tail = _AFTER_SCHEME.match(text, end)
            if tail is not None:
                cut_token = _ESC_CUT.split(tail.group(1), 1)[0]
                token = cut_token.rstrip(",;)}]")
                if len(token) >= 6 and not (
                    _is_bare_placeholder(token) or _is_bare_placeholder(cut_token)
                ):
                    t0 = tail.start(1)
                    spans.append(("secret_assignment", t0, t0 + len(token)))
            continue
        i = ns
        while i > 0 and text[i - 1] in " \t\n":
            i -= 1
        before = text[i - 1 : i] if i else ""
        spaced = m.end() > m.end("sep") or text[sep_s - 1 : sep_s] in " \t"
        env_style = sep == "=" and not spaced
        kwarg = sep == "=" and (before in ("(", ",") or run.endswith(",") or closed_by_caller)
        next_char = text[end : end + 1]
        unfinished_ok = (
            not env_style or kwarg or run.endswith(",") or next_char in ('"', "'", "`")
        )  # a call cut at `, ` continues on the next token
        is_placeholder = _is_bare_placeholder(run) or _is_bare_placeholder(value)
        same_as_name = kwarg and value.lower().rstrip("0123456789") == kw  # token=token1
        if (
            not is_placeholder
            and not same_as_name
            and _bare_is_secret(
                value,
                env_style=env_style,
                kwarg=kwarg,
                kw=kw,
                unfinished_ok=unfinished_ok,
                colon=sep == ":",
            )
        ):
            spans.append(("secret_assignment", start, start + len(value)))
            continue
        if sep == ":":  # `password: str = "..."`, the usual typed settings shape
            tail_m = _TYPED_TAIL.match(text, end)
            typed = _string_at(text, tail_m.end(), True) if tail_m is not None else None
            if typed is not None:
                start, close, resume, template = typed
                content = text[start:close]
                if (not (template and _is_template(content))) and _quoted_is_secret(
                    content,
                    name=name,
                    kw=kw,
                    package_key=False,
                    upper_const=not any(c.islower() for c in name),
                ):
                    spans.append(("secret_assignment", start, close))
    spans.extend(_env_call_spans(text))
    return spans


# --- os.getenv("SECRET_KEY", "default") ---------------------------------------------------------
_ENV_CALL = re.compile(
    r"(?<![A-Za-z0-9_])(?:getenv|get|setdefault|setenv|putenv)\([ \t]{0,8}[\"']"
    r"(?P<n>[A-Za-z0-9_.-]{0,40}(?i:password|passwd|passphrase|secret|token|api[_-]?key|apikey"
    r"|private[_-]?key|access[_-]?key|credentials?|authorization)[A-Za-z0-9_.-]{0,40})[\"']"
    r"[ \t]{0,8},[ \t]{0,8}(?:[rbfu]{1,2})?[\"'](?P<v>[^\"'\n]{4,512})[\"']"
)


def _env_call_spans(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _ENV_CALL.finditer(text):
        name = m.group("n")
        kw_m = _NAME_KW.search(name)
        kw = kw_m.group().lower() if kw_m else ""
        if _quoted_is_secret(
            m.group("v"),
            name=name,
            kw=kw,
            package_key=False,
            upper_const=not any(c.islower() for c in name),
        ):
            spans.append(("secret_assignment", m.start("v"), m.end("v")))
    return spans


# --- quoted hex under an unrelated name --------------------------------------------------------
_HEX_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<n>[A-Za-z_][A-Za-z0-9_.-]{0,60})(?:\\?[\"'])?[ \t]{0,20}"
    r"(?::=|=>|[:=])[ \t]{0,20}(?P<q>\\?[\"'])(?P<v>[0-9A-Fa-f]{32,128})(?P=q)"
)
_HASH_WORDS = frozenset({"sha", "commit", "hash", "digest", "etag", "checksum"})
_CREDENTIAL_WORDS = frozenset(
    {"secret", "token", "password", "passwd", "pass", "pwd", "key", "credential", "auth"}
)


def _hex_assignment_spans(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _HEX_ASSIGNMENT.finditer(text):
        segs = _segments(m.group("n"))
        last = segs[-1] if segs else ""
        credential_last = last in _CREDENTIAL_WORDS
        if _HASH_WORDS & set(segs) and not credential_last:
            continue  # commit_sha; but HASH_KEY and sha256_key are keys
        if last == "id" and len(m.group("v")) == 32 and not (_CREDENTIAL_WORDS & set(segs)):
            continue  # run_id, trace_id; `secret_id` stays a credential
        spans.append(("hex_assignment", m.start("v"), m.end("v")))
    return spans


# --- entropy -----------------------------------------------------------------------------------
_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{24,}")
# Public integrity hashes, by exact shape (never by prefix alone): npm/SRI and go.sum.
_PUBLIC_SHAPES = (
    re.compile(r"sha512-[A-Za-z0-9+/]{86}=="),
    re.compile(r"sha384-[A-Za-z0-9+/]{64}"),
    re.compile(r"sha256-[A-Za-z0-9+/]{43}="),
    re.compile(r"sha1-[A-Za-z0-9+/]{27}="),
)
_GO_SUM = re.compile(r"[A-Za-z0-9+/]{43}=")
_H1_BEFORE = re.compile(r"(?:^|[^A-Za-z0-9])h1:$")
_PREFIX = re.compile(r"^[A-Za-z0-9]{1,16}[-_=]")
_BASE64_SLASH = re.compile(r"[A-Za-z0-9+/=]{24,64}")
_DIGIT_RUNS = re.compile(r"\d+")
_SPLIT_SEP = re.compile(r"[-_=]+")
_B64_BODY = re.compile(r"[A-Za-z0-9+/]{24,8192}={0,2}")


def _entropy(token: str) -> float:
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in Counter(token).values())


def _is_alphabet(s: str) -> bool:
    """Ordered runs with no repeats: `ABC..Zabc..z0123456789-_`, not a random sample of them."""
    if len(s) < 32 or len(set(s)) != len(s):
        return False
    steps = sum(1 for a, b in zip(s, s[1:], strict=False) if 0 < ord(b) - ord(a) <= 3)
    return steps >= 0.85 * (len(s) - 1)


def _core_random(s: str) -> bool:
    """One run with no separators: random enough to be a secret?"""
    n = len(s)
    if n < ENTROPY_MIN_LENGTH or _entropy(s) <= ENTROPY_THRESHOLD or _is_alphabet(s):
        return False
    digits = sum(c.isdigit() for c in s)
    upper = sum(c.isupper() for c in s)
    lower = sum(c.islower() for c in s)
    if digits and lower:
        if not upper:
            return True
        # Random base62 scatters its digits in several runs; an identifier has one run of them.
        runs = len(_DIGIT_RUNS.findall(s))
        return runs >= 3 or (runs >= 2 and upper / n >= MIN_UPPER_RATIO)
    if upper and lower:
        return n >= 40 and MIN_UPPER_RATIO <= upper / n <= 0.75
    return bool(upper and digits)


def _random_looking(s: str) -> bool:
    if len(s) < ENTROPY_MIN_LENGTH:
        return False
    if not any(c in "-_=" for c in s):
        return _core_random(s)
    # Each segment on its own: `sk-live-<32 random>` must not hide behind its prefix words.
    if any(len(p) >= ENTROPY_MIN_LENGTH and _core_random(p) for p in _SPLIT_SEP.split(s)):
        return True
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    if not (has_upper and has_lower and any(c.isdigit() for c in s)):
        return False  # all-lower slugs, ALL_UPPER constants and words with separators
    return _core_random(s)


_NODE_ID = re.compile(r"\d{1,3}:[A-Z][A-Za-z]{2,30}\d{1,12}")  # GitHub legacy node ids


_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){12,2048}")


def _decoded_hex(token: str) -> str | None:
    if _HEX_TOKEN.fullmatch(token) is None:
        return None
    data = bytes.fromhex(token)
    return data.decode("ascii", "replace") if all(32 <= b < 127 for b in data) else None


def _decoded_text(token: str) -> str | None:
    body = token.rstrip("=")
    if len(body) % 4 == 1 or _B64_BODY.fullmatch(token) is None:
        return None
    try:
        data = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    return data.decode("ascii", "replace") if all(32 <= b < 127 for b in data) else None


def _token_core(token: str) -> bool:
    if "/" in token:
        if any(_random_looking(seg) for seg in token.split("/")):
            return True
        # A base64 secret holds slashes (AWS secret keys). A path holds `-`, `_` or lowercase.
        if _BASE64_SLASH.fullmatch(token) and _entropy(token) > ENTROPY_THRESHOLD:
            upper = sum(c.isupper() for c in token)
            return (
                any(c.isdigit() for c in token)
                and any(c.islower() for c in token)
                and upper / len(token) >= MIN_UPPER_RATIO
            )
        return False
    return _random_looking(token)


def _token_is_secret(token: str, before: str) -> bool:
    if any(p.fullmatch(token) for p in _PUBLIC_SHAPES):
        return False
    body = token.rstrip("=")
    if "=" in body:  # `GIT_SHA=<hex>`: judge each side on its own
        return any(_token_is_secret(part, "") for part in body.split("=") if len(part) >= 24)
    if _H1_BEFORE.search(before) and _GO_SUM.fullmatch(token):
        return False
    if _token_core(token):
        return True
    # A short prefix (`sha512-`, `key-`, `x_`) must not hide what follows it. One level only.
    stripped = _PREFIX.sub("", token, count=1)
    return stripped != token and _token_core(stripped)


def _entropy_spans(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _TOKEN.finditer(text):
        token = m.group()
        decoded = _decoded_hex(token) or _decoded_text(token)
        if decoded is not None:
            if _known_spans(decoded):  # base64 of a token in a known format
                spans.append(("encoded_secret", m.start(), m.end()))
                continue
            if _NODE_ID.fullmatch(decoded):
                continue
        before = text[max(0, m.start() - 4) : m.start()]
        if _token_is_secret(token, before):
            spans.append(("high_entropy", m.start(), m.end()))
    return spans


# --- driver ------------------------------------------------------------------------------------
_PRIORITY = {"secret_assignment": 1, "hex_assignment": 1, "high_entropy": 2}  # formats: 0


Span2 = tuple[int, int]
MIN_REMAINDER = 12  # what is left of a lower-priority span after a higher one took its part


def _subtract(span: Span2, taken: list[Span2], starts: list[int]) -> list[Span2]:
    """``span`` minus the sorted, disjoint ``taken`` intervals: one pass over the overlaps."""
    pieces: list[Span2] = []
    cursor = span[0]
    i = max(0, bisect_right(starts, span[0]) - 1)
    while i < len(taken) and taken[i][0] < span[1]:
        ts, te = taken[i]
        if te > cursor:
            if ts > cursor:
                pieces.append((cursor, ts))
            cursor = max(cursor, te)
        i += 1
    if cursor < span[1]:
        pieces.append((cursor, span[1]))
    return pieces


def _merge(spans: list[Span]) -> tuple[Finding, ...]:
    """One finding per region. A lower-priority span never widens a higher one: the `//` in front
    of `//ghp_...` stays, and only a remainder of ``MIN_REMAINDER`` characters or more survives."""
    levels: dict[int, list[tuple[int, int, str]]] = {0: [], 1: [], 2: []}
    for kind, start, end in spans:
        levels[_PRIORITY.get(kind, 0)].append((start, end, kind))
    taken: list[Span2] = []
    result: list[tuple[int, int, str]] = []
    for level in (0, 1, 2):
        starts = [t[0] for t in taken]
        kept: list[tuple[int, int, str]] = []
        for start, end, kind in sorted(levels[level]):
            for ps, pe in _subtract((start, end), taken, starts):
                if (ps, pe) == (start, end) or pe - ps >= MIN_REMAINDER:
                    kept.append((ps, pe, kind))
        kept.sort()
        merged: list[tuple[int, int, str]] = []
        for ps, pe, kind in kept:
            if merged and ps < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], pe), merged[-1][2])
            else:
                merged.append((ps, pe, kind))
        result.extend(merged)
        taken = sorted(taken + [(a, b) for a, b, _ in merged])
    result.sort()
    return tuple(Finding(kind, start, end) for start, end, kind in result)


def _run(text: object, deadline_at: float | None) -> tuple[Finding, ...]:
    if not isinstance(text, str):
        raise ScanError("scan input must be str")
    if len(text) > MAX_SCAN_CHARS:
        raise ScanError(f"scan input too large ({len(text)} chars, limit {MAX_SCAN_CHARS})")
    limit = _now() + DEADLINE_SECONDS if deadline_at is None else deadline_at
    spans: list[Span] = []
    stages: tuple[Callable[[str], list[Span]], ...] = (
        _known_spans,
        _assignment_spans,
        _hex_assignment_spans,
        _entropy_spans,
    )
    for stage in stages:
        spans.extend(stage(text))
        if _now() > limit:
            raise ScanError("scan deadline exceeded")
    found = _merge(spans)
    if _now() > limit:
        raise ScanError("scan deadline exceeded")
    return found


def scan_text(text: str, *, deadline_at: float | None = None) -> tuple[Finding, ...]:
    """Scan with an optional absolute ``time.monotonic`` deadline shared by several calls."""
    failed = False
    try:
        return _run(text, deadline_at)
    except ScanError:
        raise
    except Exception:
        failed = True
    assert failed
    # Raised outside the except block so the original error, which may quote input, is not chained.
    raise ScanError("scan failed unexpectedly")


def scan(text: str) -> tuple[Finding, ...]:
    """Return merged findings in order. Raises ``ScanError`` if the scan cannot finish."""
    return scan_text(text)


_SURROGATE = re.compile("[\ud800-\udfff]")


def redact(text: str, findings: tuple[Finding, ...]) -> str:
    parts: list[str] = []
    pos = 0
    for f in findings:
        parts.append(text[pos : f.start])
        parts.append(f"[REDACTED:{f.kind}]")
        pos = f.end
    parts.append(text[pos:])
    return "".join(parts)


def screen(text: str) -> Screened:
    """Scan ``text`` and return it with every finding replaced by ``[REDACTED:kind]``."""
    findings = scan_text(text)
    clean = _SURROGATE.sub("\ufffd", redact(text, findings))  # a lone surrogate cannot be framed
    return Screened(clean, findings)
