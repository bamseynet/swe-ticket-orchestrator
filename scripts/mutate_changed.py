"""Mutation-test the Python files under src/ that a change touches (non-blocking CI report).

For each changed ``src/**.py`` file it makes small token-level mutants (``==`` to ``!=``,
``+`` to ``-``, ``and`` to ``or``, ``True`` to ``False``, ``n`` to ``n + 1`` ...), runs only the
direct tests of that file (``scripts/test_changed.py`` mapping) plus the tests the change touches,
and lists the mutants that SURVIVE, meaning no test failed. A survivor is a behaviour no test pins.

By default only lines the change touched are mutated (``--all-lines`` mutates the whole file). A
line carrying ``# pragma: no mutate`` is never mutated. Every mutant runs in its own pytest process
with a hard timeout and an address-space cap (``ulimit -v 1500000``). Outcomes: killed, survived,
timeout, memory (MemoryError or the cap hit). Mutants that do not compile are dropped. The run
stops at a total time budget and reports what finished. It exits 0 unless the arguments are wrong.

    uv run python scripts/mutate_changed.py --base origin/main --out mutation-out
    uv run python scripts/mutate_changed.py --files src/sto/foo.py --all-lines
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
import tokenize
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_changed  # noqa: E402  (reused mapping: sibling tests of a source file)

PRAGMA = "pragma: no mutate"
MEMORY_LIMIT_KB = 1_500_000  # ulimit -v 1500000
DEFAULT_TOTAL_SECONDS = 17 * 60  # job cap is 20 minutes; leave room for setup and upload
MIN_MUTANT_TIMEOUT = 20.0
MAX_MUTANT_TIMEOUT = 120.0

SWAPS: dict[str, str] = {
    "==": "!=",
    "!=": "==",
    "<": ">=",
    ">=": "<",
    ">": "<=",
    "<=": ">",
    "+": "-",
    "-": "+",
    "and": "or",
    "or": "and",
    "True": "False",
    "False": "True",
    "is": "is not",
}

KILLED, SURVIVED, TIMEOUT, MEMORY = "killed", "survived", "timeout", "memory"


@dataclass
class Mutant:
    file: str
    line: int
    col: int
    original: str  # the original line, stripped
    mutated: str  # the mutated line, stripped
    description: str
    source: str = field(repr=False, default="")  # full mutated file text
    outcome: str = ""


def _line_ok(lines: list[str], row: int) -> bool:
    return row <= len(lines) and PRAGMA not in lines[row - 1]


def generate_mutants(
    source: str, rel: str = "", only_lines: set[int] | None = None
) -> list[Mutant]:
    """Token-level mutants of ``source`` (strings, pragma lines and uncompilable ones skipped)."""
    lines = source.splitlines(keepends=True)
    mutants: list[Mutant] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError):
        return []
    for i, tok in enumerate(tokens):
        row, col = tok.start
        if only_lines is not None and row not in only_lines:
            continue
        if not _line_ok(lines, row):
            continue
        new: str | None = None
        if tok.type in (tokenize.OP, tokenize.NAME) and tok.string in SWAPS:
            if tok.string == "is" and tokens[i + 1].string == "not":
                continue  # `is not` is handled via its `is`; mutate once at the `is`
            new = SWAPS[tok.string]
            if tok.string in "+-" and tok.type == tokenize.OP:
                prev = tokens[i - 1]
                unary = prev.type == tokenize.OP and prev.string not in ")]}"
                if unary or prev.type in (tokenize.NEWLINE, tokenize.NL, tokenize.INDENT):
                    continue  # a sign, not an operator
        elif tok.type == tokenize.NUMBER and tok.string.isdigit():
            new = str(int(tok.string) + 1)
        if new is None:
            continue
        line = lines[row - 1]
        mutated_line = line[:col] + new + line[col + len(tok.string) :]
        mutated = "".join([*lines[: row - 1], mutated_line, *lines[row:]])
        try:
            compile(mutated, rel or "<mutant>", "exec")
        except (SyntaxError, ValueError):
            continue
        mutants.append(
            Mutant(
                file=rel,
                line=row,
                col=col,
                original=line.strip(),
                mutated=mutated_line.strip(),
                description=f"{tok.string!r} -> {new!r}",
                source=mutated,
            )
        )
    return mutants


def changed_line_numbers(rel: str, base: str, root: Path) -> set[int] | None:
    """Added or changed line numbers of ``rel`` against the merge base, None if git cannot say."""
    done = subprocess.run(
        ["git", "diff", "-U0", f"{base}...HEAD", "--", rel],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        return None
    out: set[int] = set()
    for m in re.finditer(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", done.stdout, re.M):
        start, count = int(m.group(1)), int(m.group(2) or 1)
        out.update(range(start, start + count))
    return out


def _limits() -> None:
    os.setsid()
    limit = MEMORY_LIMIT_KB * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def run_tests(
    tests: Sequence[str], root: Path, timeout: float, pycache: Path
) -> tuple[str, int, str]:
    """One pytest process. Returns (outcome, returncode, output tail); outcome is
    killed/survived/timeout/memory, or 'notests'."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPYCACHEPREFIX": str(pycache)}
    cmd = [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests]
    proc = subprocess.Popen(
        cmd,
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=_limits,  # noqa: PLW1509  (setrlimit must run in the child before exec)
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return TIMEOUT, -9, ""
    tail = out[-2000:]
    rc = proc.returncode
    if "MemoryError" in out or rc in (-signal.SIGSEGV, -signal.SIGABRT, -signal.SIGKILL):
        return MEMORY, rc, tail
    if rc == 0:
        return SURVIVED, rc, tail
    if rc == 5:
        return "notests", rc, tail
    return KILLED, rc, tail


@dataclass
class FileResult:
    file: str
    tests: list[str]
    mutants: list[Mutant] = field(default_factory=list)
    skipped: str = ""  # why nothing was mutated
    unfinished: int = 0  # mutants not run because the time budget ran out


def mutate_file(
    rel: str,
    tests: list[str],
    root: Path,
    deadline: float,
    only_lines: set[int] | None,
    runner: Callable[..., tuple[str, int, str]] = run_tests,
) -> FileResult:
    result = FileResult(file=rel, tests=tests)
    path = root / rel
    if not tests:
        result.skipped = "no direct tests for this file"
        return result
    original = path.read_text()
    mutants = generate_mutants(original, rel, only_lines)
    if not mutants:
        result.skipped = "no mutable lines" + (" among the changed lines" if only_lines else "")
        return result
    with tempfile.TemporaryDirectory(prefix="mutate-pyc-") as pyc:
        started = time.monotonic()
        base_outcome, _, tail = runner(tests, root, MAX_MUTANT_TIMEOUT * 2, Path(pyc))
        if base_outcome != SURVIVED:  # "survived" here means the unmutated tests pass
            last = tail.strip().splitlines()[-1:] or [base_outcome]
            result.skipped = f"baseline tests do not pass ({base_outcome}: {last[0]})"
            return result
        per = min(MAX_MUTANT_TIMEOUT, max(MIN_MUTANT_TIMEOUT, 3 * (time.monotonic() - started)))
        try:
            for n, mutant in enumerate(mutants):
                if time.monotonic() + per > deadline:
                    result.unfinished = len(mutants) - n
                    break
                path.write_text(mutant.source)
                outcome, _, _ = runner(tests, root, per, Path(pyc))
                mutant.outcome = KILLED if outcome == "notests" else outcome
                result.mutants.append(mutant)
        finally:
            path.write_text(original)
    return result


def counts(results: Sequence[FileResult]) -> dict[str, int]:
    out = {KILLED: 0, SURVIVED: 0, TIMEOUT: 0, MEMORY: 0, "unfinished": 0}
    for r in results:
        out["unfinished"] += r.unfinished
        for m in r.mutants:
            out[m.outcome] += 1
    return out


def render_markdown(results: Sequence[FileResult], note: str = "") -> str:
    c = counts(results)
    ran = sum(c[k] for k in (KILLED, SURVIVED, TIMEOUT, MEMORY))
    out = ["## Mutation report (non-blocking)", ""]
    if note:
        out += [note, ""]
    out.append(
        f"Mutants run: **{ran}**: killed {c[KILLED]}, **survived {c[SURVIVED]}**, "
        f"timeout {c[TIMEOUT]}, memory {c[MEMORY]}"
        + (f"; not run (time budget): {c['unfinished']}" if c["unfinished"] else "")
        + ". Timeouts and memory errors are not counted as kills."
    )
    out.append("")
    survivors = [m for r in results for m in r.mutants if m.outcome == SURVIVED]
    if survivors:
        out += [
            "### Surviving mutants",
            "",
            "No test failed for these changes. Pin the behaviour or justify it.",
            "",
        ]
        for m in survivors:
            out += [
                f"- `{m.file}:{m.line}` ({m.description})",
                f"  - original: `{m.original}`",
                f"  - mutated:  `{m.mutated}`",
            ]
        out.append("")
    elif ran:
        out += ["No surviving mutants.", ""]
    skipped = [r for r in results if r.skipped]
    if skipped:
        out += ["### Files not mutated", ""]
        out += [f"- `{r.file}`: {r.skipped}" for r in skipped]
        out.append("")
    other = [m for r in results for m in r.mutants if m.outcome in (TIMEOUT, MEMORY)]
    if other:
        out += ["### Timeouts and memory errors", ""]
        out += [f"- `{m.file}:{m.line}` {m.outcome}: `{m.mutated}`" for m in other]
        out.append("")
    return "\n".join(out)


def to_json(results: Sequence[FileResult]) -> dict[str, object]:
    return {
        "counts": counts(results),
        "files": [
            {
                "file": r.file,
                "tests": r.tests,
                "skipped": r.skipped,
                "unfinished": r.unfinished,
                "mutants": [
                    {k: v for k, v in asdict(m).items() if k != "source"} for m in r.mutants
                ],
            }
            for r in results
        ],
    }


def main(argv: Sequence[str] | None = None, *, root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--files", nargs="*", help="mutate these src files instead of the git diff")
    parser.add_argument(
        "--all-lines", action="store_true", help="mutate whole files, not just changed lines"
    )
    parser.add_argument("--total-seconds", type=float, default=DEFAULT_TOTAL_SECONDS)
    parser.add_argument(
        "--out", default="mutation-out", help="directory for mutation-report.md and .json"
    )
    args = parser.parse_args(argv)
    root = root or Path(__file__).resolve().parent.parent
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        changed = (
            list(args.files)
            if args.files is not None
            else test_changed.changed_files(args.base, root)
        )
    except test_changed.GitError as err:
        note = f"Could not list changed files ({err}). Nothing was mutated."
        _write(out_dir, [], note)
        return 0
    sources = [
        f for f in changed if f.startswith("src/") and f.endswith(".py") and (root / f).is_file()
    ]
    if not sources:
        _write(out_dir, [], "No Python source changed under `src/`: nothing to mutate.")
        return 0
    changed_tests = [
        f for f in changed if f.startswith("tests/") and Path(f).name.startswith("test_")
    ]
    deadline = time.monotonic() + args.total_seconds
    results: list[FileResult] = []
    for rel in sorted(sources):
        sibling = test_changed.select([rel], root, budget=50).paths
        tests = sorted({*sibling, *(t for t in changed_tests if (root / t).is_file())})
        only = None if args.all_lines else changed_line_numbers(rel, args.base, root)
        results.append(mutate_file(rel, tests, root, deadline, only))
    note = f"Base `{args.base}`, {len(sources)} changed source file(s)."
    _write(out_dir, results, note)
    return 0


def _write(out_dir: Path, results: Sequence[FileResult], note: str) -> None:
    md = render_markdown(results, note)
    (out_dir / "mutation-report.md").write_text(md)
    (out_dir / "mutation-report.json").write_text(json.dumps(to_json(results), indent=2))
    print(md)


if __name__ == "__main__":
    raise SystemExit(main())
