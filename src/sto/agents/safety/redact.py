"""Error redaction at one boundary (D5-04, threat T5).

``redact_error`` is the only way error text should leave a step for a reviewer, a comment, a log
or a stored record. Over-redacting an error is cheap, so it is aggressive: it removes URLs, ARNs,
hosts and IPs, every path (absolute, relative, UNC, with spaces), ``key=value`` pairs with secret
names, and secrets. Raw errors stay with operators, outside this module. If redaction itself
fails, the fixed ``REDACTION_FAILED`` text is returned, never the input. The result is always
valid UTF-8, and absent or unsupported input gets a clear placeholder, never an empty string.
"""

from __future__ import annotations

import re

from sto.agents.safety.scanner import screen

MAX_ERROR_CHARS = 2000
REDACTION_FAILED = "[error text withheld: redaction failed]"
NO_ERROR_TEXT = "[no error text]"
_INPUT_CAP = MAX_ERROR_CHARS * 16
_CHAIN_DEPTH = 5

# Each pattern starts on a literal or a run boundary and its unbounded part is last, so each is
# linear (see scanner.py). Order matters: whole URLs first, then hosts, then paths.
_LOCATIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{1,20}://[^\s\"'<>]*"), "[URL]"),
    (re.compile(r"(?i)(?<![a-z0-9])arn:aws[a-z-]{0,20}:[^\s\"'<>]*"), "[ARN]"),
    # host='db.internal', host="x", hostname: y
    (re.compile(r"(?i)\b(host(?:name)?)([ \t]{0,3}[=:][ \t]{0,3})(['\"])[^'\"]*\3"), r"\1\2[HOST]"),
    (re.compile(r"(?i)\b(host(?:name)?)([ \t]{0,3}=[ \t]{0,3})[^\s'\",;)]+"), r"\1\2[HOST]"),
    (
        re.compile(r"(?<![\w.-])[\w.-]{1,40}(?::[^\s@]{1,100})?@[\w.-]{1,100}(?::[\w./~-]+)?"),
        "[URL]",
    ),
    # Quoted strings that hold a slash: the whole quoted string, spaces included. The first class
    # stops at the first slash, so the match is linear.
    (re.compile(r"""(['"])[^'"\n/\\]*[/\\][^'"\n]*\1"""), "[PATH]"),
    # UNC, drive and absolute paths run to the end of the line, because they may hold spaces.
    (re.compile(r"(?<![\w])\\\\[^\s\"'<>][^\"'<>\n]*"), "[PATH]"),
    (re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\"'<>\n]*"), "[PATH]"),
    (re.compile(r"(?<![\w.~$%])(?:~|\$\w+|%\w+%)?/[^\s\"'<>/][^\"'<>\n]*"), "[PATH]"),
    # Everything else with a slash in it, such as config/prod/db.yml or repos/acme/x/pulls/3.
    (re.compile(r"(?<![^\s\"'<>()=,;])[^\s\"'<>()=,;]*[/\\][^\s\"'<>()]*"), "[PATH]"),
    (re.compile(r"\[[0-9A-Fa-f:.]{2,45}\](?::\d{1,5})?"), "[HOST]"),
    (re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:.])"), "[HOST]"),
    (re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?![\w.])"), "[HOST]"),
    (re.compile(r"(?<![\w.-])[A-Za-z][\w-]{0,62}:\d{2,5}(?![\w-])"), "[HOST]"),
    (re.compile(r"(?i)(?<![\w.-])localhost(?::\d{1,5})?"), "[HOST]"),
    (
        re.compile(
            r"(?i)(?<![\w.-])[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63}){1,8}(?::\d{1,5})?(?![\w-])"
        ),
        "[HOST]",
    ),
)
# `Authorization: Bearer abc` is one value: the scheme word goes with its token.
_SECRET_PAIR = re.compile(
    r"(?i)((?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|credentials?|authorization|bearer|(?<![a-z0-9])(?:pass|auth)(?![a-z0-9]))"
    r"[\w.-]{0,32}[ \t]{0,3}[=:][ \t]{0,3})"
    r"(?:(?:bearer|basic|token|digest|negotiate)[ \t]+)?[^\s\"',;]+"
)
_BEARER = re.compile(r"(?i)(?<![A-Za-z])(bearer[ \t]{1,8})[^\s\"',;]+")


def _safe_str(obj: object) -> str:
    try:
        return str(obj)
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:
        return "<unprintable>"


def _describe(err: BaseException | str) -> str:
    if isinstance(err, str):
        return err
    parts: list[str] = []
    seen: BaseException | None = err
    for _ in range(_CHAIN_DEPTH):
        if seen is None:
            break
        line = f"{type(seen).__name__}: {_safe_str(seen)}"
        notes = getattr(seen, "__notes__", None)
        if isinstance(notes, list):
            line += "".join(f" [note: {_safe_str(n)}]" for n in notes[:5])
        parts.append(line)
        sub = getattr(seen, "exceptions", None)
        if isinstance(sub, tuple | list):
            parts.extend(f"{type(e).__name__}: {_safe_str(e)}" for e in sub[:5])
        seen = seen.__cause__ or seen.__context__
    return " <- ".join(parts)


def redact_error(err: BaseException | str | None) -> str:
    """Return a bounded, UTF-8 error string with locations and secrets removed."""
    try:
        if err is None:
            return NO_ERROR_TEXT
        if not isinstance(err, BaseException | str):
            return f"[unsupported error value: {type(err).__name__}]"
        text = _describe(err)[:_INPUT_CAP]
        text = text.encode("utf-8", "replace").decode("utf-8")  # lone surrogates become `?`
        if not text.strip():
            return NO_ERROR_TEXT
        for pattern, label in _LOCATIONS:
            text = pattern.sub(label, text)
        text = _SECRET_PAIR.sub(r"\1[REDACTED:secret_assignment]", text)
        text = _BEARER.sub(r"\1[REDACTED:bearer]", text)
        text = screen(text).text
        if len(text) > MAX_ERROR_CHARS:
            text = text[:MAX_ERROR_CHARS] + "[truncated]"
        return text
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:
        return REDACTION_FAILED
