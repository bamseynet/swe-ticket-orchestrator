"""The git edge of carry-over (D2-31): merge base, changed files and the canonical diff, read from
a checkout. Impure (it runs ``git``), so it lives outside ``sto.engine``, whose modules must be
pure. Every failure is :class:`~sto.engine.handlers.carry.CarryRefused`, never an empty answer."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from sto.engine.handlers.carry import CarryRefused, parse_name_only_z

__all__ = ["GitReader"]

_GIT_TIMEOUT_S = 60.0


class GitReader:
    """Reads the facts carry-over needs from a checkout of the run's repository.

    Every call is ``git`` with a clean environment (no user or system config) and a bounded time.
    A non-zero exit, a timeout or output that does not parse is :class:`CarryRefused`, never an
    empty answer: an empty list is also what a failed read looks like. ``base_ref`` is the
    branch the run merges into; the *merge base of a head* is measured against it."""

    def __init__(self, repo: Path | str, base_ref: str) -> None:
        if not str(base_ref).strip():
            raise ValueError("base_ref must not be blank")
        self._repo, self._base_ref = str(repo), base_ref

    def _run(self, *args: str) -> bytes:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        try:
            done = subprocess.run(
                ["git", "-C", self._repo, *args],
                capture_output=True,
                timeout=_GIT_TIMEOUT_S,
                check=False,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CarryRefused(f"git could not run: {exc}") from exc
        if done.returncode != 0:
            why = done.stderr.decode(errors="replace").strip()
            raise CarryRefused(f"git {args[0]} failed: {why}")
        return done.stdout

    def merge_base(self, head: str) -> str:
        out = self._run("merge-base", self._base_ref, head).decode().strip()
        if not out or "\n" in out:
            raise CarryRefused(f"no single merge base for {head}")
        return out

    def files(self, from_commit: str, to_commit: str) -> frozenset[str]:
        """Paths changed between two commits: ``git diff --name-only -z --no-renames``, so both
        sides of a rename appear. Whole or refused."""
        return parse_name_only_z(
            self._run("diff", "--name-only", "-z", "--no-renames", from_commit, to_commit)
        )

    def diff(self, merge_base: str, head: str) -> bytes:
        """The canonical diff ``patch_id`` is taken over (see ``gates/subject.py``).

        The repository's own config must not change the bytes (and so the patch id): the
        settings that do are pinned on the command line, which outranks any config file, and
        the options are explicit. Renames are off (both sides appear as a delete and an add),
        context is three lines, the prefixes are ``a/`` and ``b/``."""
        pinned = (
            "diff.renames=false",
            "diff.context=3",
            "diff.noprefix=false",
            "diff.mnemonicPrefix=false",
            "diff.srcPrefix=a/",
            "diff.dstPrefix=b/",
            "diff.algorithm=myers",
            "diff.indentHeuristic=false",
            "diff.interHunkContext=0",
            "diff.external=",
            "core.quotePath=true",
            "core.autocrlf=false",
        )
        flags = [f for key in pinned for f in ("-c", key)]
        return self._run(
            *flags, "diff", "--binary", "--no-color", "--no-ext-diff", "--full-index",
            "--no-renames", "-U3", "--src-prefix=a/", "--dst-prefix=b/", merge_base, head,
        )  # fmt: skip
