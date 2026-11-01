"""Patch scan before push (D5-04, threat T4).

``check_patch`` reads a unified diff, scans the text of every *added* line and every path in the
headers, and raises ``PatchBlockedError`` on any finding. That error is a ``PermanentError``: the
step blocks, and a patch blocked by a secret scan is never routed past ``branch.push`` (PLAN,
route-to-gate). It reports kind, path and line only, never the text.

Lines are split on ``\\n`` only, exactly as git does. ``str.splitlines`` also splits on form feed,
``\\r``, U+2028 and others, which would let the tail of an added line be read as a header.

Fail closed: a diff that cannot be parsed, a binary patch, or an oversize patch raises
``ScanError`` instead of passing. A patch has an overall size limit and an overall wall-clock
backstop on top of the per-file limit in the scanner.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from time import monotonic

from sto.agents.safety.scanner import ScanError, scan_text, screen
from sto.domain.errors import PermanentError

MAX_PATCH_CHARS = 4_000_000
PATCH_DEADLINE_SECONDS = 240.0

_HUNK = re.compile(r"@@ -\d{1,9}(?:,(\d{1,9}))? \+(\d{1,9})(?:,(\d{1,9}))? @@")
_HEADER_PREFIXES = (
    "diff ",
    "index ",
    "--- ",
    "+++ ",
    "new file mode",
    "deleted file mode",
    "old mode",
    "new mode",
    "similarity index",
    "dissimilarity index",
    "rename ",
    "copy ",
)
_PATH_PREFIXES = (
    "diff --git ",
    "--- ",
    "+++ ",
    "+++ ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_C_ESCAPE = re.compile(r'\\([0-7]{3}|[abfnrtv\\"])')
_SIMPLE = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}


@dataclass(frozen=True)
class PatchFinding:
    path: str
    line: int  # 0 for a path in a header
    kind: str


HINT = (
    "Correct the patch. A fake value in a test may be written as exactly test, fake, mock, dummy "
    "or example, optionally followed by -token, -key, -secret or -password; or as one of wrong, "
    "bad, invalid, expired, other, good or nope with the same optional suffix."
)


class PatchBlockedError(PermanentError):
    def __init__(self, findings: tuple[PatchFinding, ...]) -> None:
        self.findings = findings
        shown = ", ".join(f"{f.kind} at {f.path}:{f.line}" for f in findings[:20])
        more = f" (+{len(findings) - 20} more)" if len(findings) > 20 else ""
        super().__init__(f"patch blocked by secret scan: {shown}{more}. {HINT}")


def _malformed() -> ScanError:
    return ScanError("patch could not be parsed")


def _unquote(path: str) -> str:
    """Undo git's C-style quoting (``"b/\\303\\244.py"``) so a secret cannot hide in escapes."""
    if "\\" not in path:
        return path
    out = bytearray()
    pos = 0
    for m in _C_ESCAPE.finditer(path):
        out += path[pos : m.start()].encode("utf-8", "replace")
        code = m.group(1)
        out.append(int(code, 8) & 0xFF if code[0] in "01234567" else _SIMPLE[code])
        pos = m.end()
    out += path[pos:].encode("utf-8", "replace")
    return out.decode("utf-8", "replace")


def _safe_path(path: str) -> str:
    """A path to show a reviewer: unquoted, bounded, and screened like any other text."""
    shown = screen(_unquote(path)).text[:500]
    return _CONTROL.sub("?", shown)  # a newline in a name must not forge a line in the error


@dataclass
class _File:
    path: str = ""
    headers: list[str] | None = None
    added: list[tuple[int, str]] | None = None

    def __post_init__(self) -> None:
        self.headers = []
        self.added = []


def _scan_file(f: _File, deadline_at: float) -> list[PatchFinding]:
    assert f.headers is not None
    assert f.added is not None
    name = f.path
    if not name and f.headers:
        name = f.headers[0].removeprefix("diff --git ").rsplit(" b/", 1)[-1]
    shown = _safe_path(name)
    out: list[PatchFinding] = []
    if f.headers:
        header_text = "\n".join(_unquote(h) for h in f.headers)
        out.extend(
            PatchFinding(shown, 0, x.kind) for x in scan_text(header_text, deadline_at=deadline_at)
        )
    if f.added:
        text = "\n".join(content for _, content in f.added)
        starts: list[int] = []
        pos = 0
        for _, content in f.added:
            starts.append(pos)
            pos += len(content) + 1
        for x in scan_text(text, deadline_at=deadline_at):
            out.append(PatchFinding(shown, f.added[bisect_right(starts, x.start) - 1][0], x.kind))
    return out


def scan_patch(patch: str) -> tuple[PatchFinding, ...]:
    failed = False
    try:
        return _scan_patch(patch)
    except ScanError:
        raise
    except Exception:
        failed = True
    assert failed
    raise ScanError("patch scan failed unexpectedly")


def _scan_patch(patch: str) -> tuple[PatchFinding, ...]:
    if not isinstance(patch, str):
        raise ScanError("patch must be str")
    if len(patch) > MAX_PATCH_CHARS:
        raise ScanError("patch too large to scan")
    deadline_at = monotonic() + PATCH_DEADLINE_SECONDS
    findings: list[PatchFinding] = []
    lines = patch.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    current = _File()
    started = False
    old_left = new_left = new_line = 0
    in_hunk = False

    for raw in lines:
        if in_hunk:
            tag, content = raw[:1], raw[1:]
            if tag == "\\":
                continue
            if tag in (" ", ""):
                old_left, new_left, new_line = old_left - 1, new_left - 1, new_line + 1
            elif tag == "-":
                old_left -= 1
            elif tag == "+":
                if "\x00" in content:
                    # UTF-16/32 or binary text: its bytes are not what a scan of the characters
                    # sees, yet `git apply` writes them.
                    raise ScanError("patch holds NUL bytes and cannot be scanned")
                new_left, new_line = new_left - 1, new_line + 1
                assert current.added is not None
                current.added.append((new_line - 1, content))
            else:
                raise _malformed()
            if old_left < 0 or new_left < 0:
                raise _malformed()
            in_hunk = old_left > 0 or new_left > 0
            continue
        if raw.startswith("\\"):  # `\ No newline at end of file`, after the hunk's last line
            continue
        if raw.startswith("@@"):
            m = _HUNK.match(raw)
            if m is None or not started:
                raise _malformed()
            old_left = int(m.group(1)) if m.group(1) is not None else 1
            new_left = int(m.group(3)) if m.group(3) is not None else 1
            new_line = int(m.group(2))
            in_hunk = old_left > 0 or new_left > 0
            continue
        if raw.startswith("diff "):
            if started:
                findings.extend(_scan_file(current, deadline_at))
            current, started = _File(), True
        elif not started and raw:
            raise _malformed()
        elif raw.startswith(("Binary files", "GIT binary patch")):
            raise ScanError("binary patch cannot be scanned")
        elif raw and not raw.startswith(_HEADER_PREFIXES):
            raise _malformed()
        if raw.startswith(_PATH_PREFIXES):
            assert current.headers is not None
            current.headers.append(raw)
            if raw.startswith(("+++ ", "rename to ", "copy to ")) or (
                raw.startswith("--- ") and not current.path
            ):
                target = _unquote(raw.split(" ", 2)[-1] if raw[0] in "rc" else raw[4:])
                target = target.split("\t")[0].strip('"')
                if target != "/dev/null":
                    current.path = target.removeprefix("b/").removeprefix("a/")
    if in_hunk:
        raise _malformed()
    if started:
        findings.extend(_scan_file(current, deadline_at))
    return tuple(dict.fromkeys(findings))


def check_patch(patch: str) -> None:
    """Raise ``PatchBlockedError`` if any added line or path holds a finding."""
    found = scan_patch(patch)
    if found:
        raise PatchBlockedError(found)
