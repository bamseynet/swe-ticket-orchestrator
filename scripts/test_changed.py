"""Run the direct tests of the files changed against main (D0-08).

Direct tests only: a change in a widely used package such as ``src/sto/domain/`` selects the tests
that belong to that module, never the whole suite. A selection budget caps the count, and what
does not fit is left to CI. Shared files (lockfiles, CI, Makefile, docs) select nothing here.

    uv run python scripts/test_changed.py [--base origin/main] [--budget N] [--files F ...]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BUDGET = 25


@dataclass
class Selection:
    paths: list[str] = field(default_factory=list)
    over_budget: list[str] = field(default_factory=list)

    def message(self) -> str:
        if not self.paths:
            return "test-changed: no direct tests for the changed files (CI runs the rest)"
        note = f"test-changed: {len(self.paths)} direct test file(s)"
        if self.over_budget:
            note += f"; {len(self.over_budget)} over the budget left to CI"
        return note


def _candidates(rel: str) -> list[str]:
    """Direct test paths for one changed file, most specific first."""
    path = Path(rel)
    name = path.name
    if rel.startswith("tests/") and name.startswith("test_") and path.suffix == ".py":
        return [rel]
    if name == "conftest.py" and rel.startswith("tests/"):
        return [f"{path.parent.as_posix()}/*"]  # sibling tests, not recursive
    if rel.startswith("src/sto/") and path.suffix == ".py":
        sub = Path(rel).relative_to("src/sto")
        return [(Path("tests") / sub.parent / f"test_{sub.name}").as_posix()]
    if rel.startswith("tools/") and path.suffix == ".py" and not name.startswith("test_"):
        return [(path.parent / f"test_{name}").as_posix()]
    if rel.startswith("tools/") and name.startswith("test_") and path.suffix == ".py":
        return [rel]
    if rel.startswith("scripts/") and path.suffix == ".py":
        return [(Path("tests/scripts") / f"test_{name}").as_posix()]
    return []


def select(changed: Sequence[str], root: Path, budget: int = DEFAULT_BUDGET) -> Selection:
    found: set[str] = set()
    for rel in changed:
        for cand in _candidates(rel):
            if cand.endswith("/*"):
                folder = root / cand[:-2]
                if folder.is_dir():
                    found.update(p.relative_to(root).as_posix() for p in folder.glob("test_*.py"))
            elif (root / cand).is_file():
                found.add(cand)
    ordered = sorted(found)
    return Selection(paths=ordered[:budget], over_budget=ordered[budget:])


def changed_files(base: str, root: Path) -> list[str]:
    def git(*args: str) -> list[str]:
        out = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, check=False
        ).stdout
        return out.splitlines()

    files = {
        *git("diff", "--name-only", f"{base}...HEAD"),
        *git("diff", "--name-only", "HEAD"),
        *git("ls-files", "-o", "--exclude-standard"),
    }
    return sorted(f for f in files if f)


def _run(cmd: list[str]) -> int:
    return subprocess.run(cmd, check=False).returncode


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path | None = None,
    runner: Callable[[list[str]], int] = _run,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    parser.add_argument("--files", nargs="*", help="use these changed files instead of git")
    args = parser.parse_args(argv)
    root = root or Path(__file__).resolve().parent.parent
    changed = args.files if args.files is not None else changed_files(args.base, root)
    selection = select(changed, root, args.budget)
    print(selection.message())
    if not selection.paths:
        return 0
    return runner([sys.executable, "-m", "pytest", "-q", *selection.paths])


if __name__ == "__main__":
    raise SystemExit(main())
