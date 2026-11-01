#!/usr/bin/env python3
"""Declared-files check (D0-10): a PR may touch only the files its issue declares.

Reads the PR's single ``Closes #N`` line, finds that issue's ``Files`` (docs/STAGES.md at the
base commit is the authority; the generated issue body is the fallback), and fails if the PR
touches anything else. An allow-list (lockfiles, ``pyproject.toml``, ``Makefile``,
``web/package.json``, docs) and the sibling tests of declared files are always fine. Touching a
serial area needs the issue to be serial.

An override is the ``scope-override`` label, honoured only when the *actor of its labeled event*
is on the comma-separated ``SCOPE_OVERRIDE_ACTORS`` list (the repo variable of that name). Empty
or unset means no override is possible. A label added by a worker, or re-added by one, is ignored.

Runs on ``pull_request`` with the default read-only ``GITHUB_TOKEN`` and no secrets, so it works
for fork PRs. It uses the REST API only (no checkout of PR code, nothing from the PR is executed).

    GITHUB_TOKEN=... GITHUB_REPOSITORY=o/r PR_NUMBER=5 BASE_SHA=... python scripts/check_scope.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Protocol

OVERRIDE_LABEL = "scope-override"
OVERRIDE_ACTORS_ENV = "SCOPE_OVERRIDE_ACTORS"

SERIAL_AREAS = (
    ".github/workflows/ci.yml",
    "src/sto/engine/reducer.py",
    "src/sto/engine/commands.py",
    "src/sto/domain/",
    "src/sto/gates/service.py",
)
# The check and its workflow: only D0-10 itself may edit them, whatever any declaration says.
PROTECTED = (".github/workflows/scope.yml", "scripts/check_scope.py")
PROTECTED_OWNER = "D0-10"
ALLOW_EXACT = frozenset({"pyproject.toml", "Makefile", "uv.lock", "web/package.json", "README.md"})
ALLOW_NAMES = frozenset({"package-lock.json", "uv.lock"})  # lockfiles anywhere
# Docs are free, except the spec the check itself trusts and the decision records.
ALLOW_DOCS_PREFIX = "docs/"
DENY_DOCS = ("docs/STAGES.md", "docs/adr/")

_CLOSE_RE = re.compile(
    r"^[ \t]*(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)[ \t]*:?[ \t]+#(\d+)[ \t]*$", re.I | re.M
)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_ID_RE = re.compile(r"\[(D\d+-\d+[a-z]?)\]")
_STAGES_LINE_RE = re.compile(r"\*\*Run:\*\*\s*(\S+?)\.\s*\*\*Files:\*\*\s*(.*)$")


@dataclass
class Declared:
    files: list[str]
    serial: bool


@dataclass
class Result:
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Api(Protocol):
    def pr(self) -> dict[str, Any]: ...
    def pr_files(self) -> list[str]: ...
    def issue(self, number: int) -> dict[str, Any] | None: ...
    def label_events(self) -> list[dict[str, Any]]: ...
    def stages_text(self) -> str | None: ...


# ---------------------------------------------------------------- parsing


def parse_closing_issues(body: str | None) -> list[int]:
    """Issue numbers from ``Closes #N`` lines (own line only), de-duplicated, in order."""
    text = _COMMENT_RE.sub("", (body or "").replace("\r", ""))
    found: list[int] = []
    for m in _CLOSE_RE.finditer(text):
        n = int(m.group(1))
        if n not in found:
            found.append(n)
    return found


def issue_id_from_title(title: str) -> str | None:
    """The ``[Dx-yy]`` ID in a title (an optional trailing letter marks a follow-up)."""
    m = _ID_RE.search(title or "")
    return m.group(1) if m else None


def _backticked(text: str) -> list[str]:
    return re.findall(r"`([^`]+)`", text)


def declared_from_stages(text: str, issue_id: str) -> Declared | None:
    """Files and run mode from the ``#### <id>:`` section of STAGES.md."""
    in_section = False
    for line in text.splitlines():
        if line.startswith("#### "):
            in_section = line.startswith(f"#### {issue_id}:")
            continue
        if in_section:
            m = _STAGES_LINE_RE.search(line)
            if m:
                return Declared(
                    files=_backticked(m.group(2)), serial=m.group(1).lower() == "serial"
                )
    return None


# ---------------------------------------------------------------- matching


def _under(path: str, entry: str) -> bool:
    if entry.endswith("/"):
        return path.startswith(entry)
    return path == entry


def _sibling_test(src: str) -> str | None:
    """The test path that belongs to a declared module (same mapping as scripts/test_changed.py)."""
    p = PurePosixPath(src)
    if p.suffix != ".py":
        return None
    if src.startswith("src/sto/"):
        sub = p.relative_to("src/sto")
        return (PurePosixPath("tests") / sub.parent / f"test_{sub.name}").as_posix()
    if src.startswith("scripts/"):
        return (PurePosixPath("tests/scripts") / f"test_{p.name}").as_posix()
    return None


def is_allowed(path: str, declared: Declared) -> bool:
    if any(_under(path, f) for f in declared.files):
        return True
    if path in ALLOW_EXACT or PurePosixPath(path).name in ALLOW_NAMES:
        return True
    if path.startswith(ALLOW_DOCS_PREFIX) and not any(_under(path, d) for d in DENY_DOCS):
        return True
    return any(_sibling_test(f) == path for f in declared.files)


def serial_areas_touched(paths: Sequence[str]) -> list[str]:
    return [p for p in paths if any(_under(p, a) for a in SERIAL_AREAS)]


# ---------------------------------------------------------------- override


def parse_actors(raw: str | None) -> frozenset[str]:
    """Comma-separated logins, lower-cased. Empty or unset means nobody may override."""
    return frozenset(a.strip().lower() for a in (raw or "").split(",") if a.strip())


def override_active(
    events: Sequence[dict[str, Any]],
    present: set[str] | frozenset[str],
    actors: set[str] | frozenset[str],
) -> bool:
    """True when the label is present and its latest ``labeled`` event is by a listed human."""
    if OVERRIDE_LABEL not in present:
        return False
    allowed = {a.lower() for a in actors}
    last_actor: str | None = None
    for e in events:
        if e.get("label") != OVERRIDE_LABEL:
            continue
        if e.get("event") == "labeled":
            last_actor = str(e.get("actor") or "").lower()
        elif e.get("event") == "unlabeled":
            last_actor = None
    return last_actor is not None and last_actor in allowed


# ---------------------------------------------------------------- the check


def _resolve(api: Api, number: int, pr_title: str) -> tuple[str, Declared | None, str | None]:
    """(label for messages, declaration, error). Declared files come from STAGES.md only."""
    issue = api.issue(number)
    if issue is None:
        return f"#{number}", None, f"PR links issue #{number}, which could not be read."
    iid = issue_id_from_title(str(issue.get("title", "")))
    name = f"#{number} ({iid})" if iid else f"#{number}"
    if str(issue.get("state", "")).lower() != "open":
        return name, None, f"Issue {name} is not open: a PR must close an open issue."
    if iid is None:
        return name, None, f"Issue {name} has no [Dx-yy] ID in its title."
    pr_id = issue_id_from_title(pr_title)
    if pr_id != iid:
        return name, None, f"PR title ID ({pr_id or 'none'}) must equal the issue's ID ({iid})."
    stages = api.stages_text()
    declared = declared_from_stages(stages, iid) if stages else None
    if declared is None:
        return (
            name,
            None,
            f"Issue {name} is not in docs/STAGES.md at the base commit: add it to STAGES.md first.",
        )
    return name, declared, None


def check(api: Api, override_actors: set[str] | frozenset[str] = frozenset()) -> Result:
    res = Result()
    pr = api.pr()
    overridden = override_active(api.label_events(), set(pr.get("labels") or []), override_actors)

    def fail(msg: str) -> None:
        if overridden:
            res.notes.append(f"override by listed human, would fail: {msg}")
        else:
            res.errors.append(msg)

    closing = parse_closing_issues(pr.get("body"))
    if not closing:
        fail("PR has no linked issue: put `Closes #N` on its own line in the PR body.")
        return res
    if len(closing) > 1:
        refs = ", ".join(f"#{n}" for n in closing)
        fail(f"PR closes more than one issue ({refs}). One issue, one PR.")
        return res

    name, declared, error = _resolve(api, closing[0], str(pr.get("title") or ""))
    if declared is None:
        fail(error or f"cannot resolve {name}")
        return res

    touched = sorted(set(api.pr_files()))
    undeclared = [p for p in touched if not is_allowed(p, declared)]
    if undeclared:
        listing = ", ".join(undeclared)
        fail(
            f"Files outside the declared list of issue {name}: {listing}. "
            "Declare them in docs/STAGES.md, split the PR, or ask a maintainer for the "
            f"`{OVERRIDE_LABEL}` label."
        )
    owner = issue_id_from_title(str((api.issue(closing[0]) or {}).get("title", "")))
    guarded = [p for p in touched if p in PROTECTED]
    if guarded and owner != PROTECTED_OWNER:
        fail(
            f"PR touches {', '.join(guarded)}, which only issue {PROTECTED_OWNER} may edit "
            f"(this PR closes issue {name})."
        )
    shared = serial_areas_touched(touched)
    if shared and not declared.serial:
        fail(
            f"PR touches serial area(s) {', '.join(shared)} but issue {name} is not marked serial. "
            "Mark the issue serial in docs/STAGES.md first."
        )
    if overridden and not res.errors and res.notes:
        res.notes.append(f"{OVERRIDE_LABEL} applied for issue {name}.")
    return res


# ---------------------------------------------------------------- GitHub API (read-only)


class GitHubApi:
    def __init__(self, token: str, repo: str, pr_number: int, base_sha: str) -> None:
        self.token = token
        self.repo = repo
        self.number = pr_number
        self.base_sha = base_sha

    def _get(self, path: str, accept: str = "application/vnd.github+json") -> tuple[Any, str]:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{self.repo}/{path}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": accept,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
            return resp.read().decode(), resp.headers.get("Link", "")

    def _paged(self, path: str) -> list[Any]:
        out: list[Any] = []
        page = 1
        while True:
            sep = "&" if "?" in path else "?"
            raw, link = self._get(f"{path}{sep}per_page=100&page={page}")
            out.extend(json.loads(raw))
            if 'rel="next"' not in link:
                return out
            page += 1

    def pr(self) -> dict[str, Any]:
        raw, _ = self._get(f"pulls/{self.number}")
        data = json.loads(raw)
        return {
            "title": data.get("title", ""),
            "body": data.get("body"),
            "labels": [lb["name"] for lb in data.get("labels", [])],
        }

    def pr_files(self) -> list[str]:
        paths: list[str] = []
        for f in self._paged(f"pulls/{self.number}/files"):
            paths.append(f["filename"])
            if f.get("previous_filename"):
                paths.append(f["previous_filename"])
        return paths

    def issue(self, number: int) -> dict[str, Any] | None:
        try:
            raw, _ = self._get(f"issues/{number}")
        except urllib.error.HTTPError:
            return None
        data = json.loads(raw)
        if "pull_request" in data:
            return None
        return {
            "title": data.get("title", ""),
            "state": data.get("state", ""),
        }

    def label_events(self) -> list[dict[str, Any]]:
        return [
            {
                "event": e["event"],
                "actor": (e.get("actor") or {}).get("login", ""),
                "label": (e.get("label") or {}).get("name"),
            }
            for e in self._paged(f"issues/{self.number}/events")
            if e.get("event") in ("labeled", "unlabeled")
        ]

    def stages_text(self) -> str | None:
        # The base commit, never the PR head: a PR cannot widen its own declaration.
        try:
            raw, _ = self._get(
                f"contents/docs/STAGES.md?ref={self.base_sha}",
                accept="application/vnd.github.raw+json",
            )
        except urllib.error.HTTPError:
            return None
        return str(raw)


def main(argv: Sequence[str] | None = None, api: Api | None = None) -> int:
    if api is None:
        env = os.environ
        missing = [
            v
            for v in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "PR_NUMBER", "BASE_SHA")
            if not env.get(v)
        ]
        if missing:
            print(f"check_scope: missing environment: {', '.join(missing)}")
            return 2
        api = GitHubApi(
            env["GITHUB_TOKEN"], env["GITHUB_REPOSITORY"], int(env["PR_NUMBER"]), env["BASE_SHA"]
        )
    try:
        res = check(api, parse_actors(os.environ.get(OVERRIDE_ACTORS_ENV)))
    except urllib.error.URLError as exc:
        print(f"check_scope: GitHub API error: {exc}")
        return 2
    for note in res.notes:
        print(f"check_scope: {note}")
    for err in res.errors:
        print(f"check_scope: FAIL: {err}")
    if not res.errors:
        print("check_scope: ok")
    return 1 if res.errors else 0


if __name__ == "__main__":
    sys.exit(main())
