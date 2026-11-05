"""An in-process fake of GitHub's pull request, merge, ref and commit REST routes (D4-19).

This is a SERVER, not an adapter. It has no port and holds no real credential: every ID, SHA, key
and token is synthetic. An adapter under test talks to ``FakeGitHubPulls.request`` as it would talk
to ``https://api.github.com``. It extends the auth fake of D4-16 (``FakeGitHubAuth``), so tokens,
permissions, repository narrowing, rate limits, faults and 401s are that fake's, unchanged.

Standard (as for the Jira fakes, D6-01 and D6-09): at least as strict as GitHub's documented REST
API wherever a wrong adapter would otherwise pass (types, enums, required fields, expected-head
checks, fast-forward-only ref moves, one pending merge per PR), and never stricter than documented
GitHub on a correct adapter's path (unknown body keys are ignored, as GitHub ignores them; owner
and repository are not case sensitive). Each route names its page in ``SOURCES``; each behaviour
that no page documents is in the list below, or says "unsourced" where it is implemented. The live
suite (D4-23, D12) proves all of it against the real service, and when they disagree the fake is
wrong.

The async merge is the main path: ``PUT .../pulls/{n}/merge-async`` answers 202 with a UUID, and
``GET .../merge-async/{uuid}`` reports ``pending``, then ``merged``, ``enqueued`` or ``failed``.
Documentation for it is a REST page and a changelog, with no error codes for a moved head, so
EVERYTHING about it other than the documented shape is unverified until D4-23.

Known departures, each deliberate:

* Time is the fake's ``now`` (seconds, as in ``FakeGitHubAuth``). A merge request runs when the
  caller has polled it ``pending_polls`` times (default 1 pending answer, then the run) or when a
  test calls ``settle()``; GitHub gives no such number. Request results expire 24 hours after their
  last update (documented); the fake counts that on ``now``.
* Unsourced answers, to prove live (D4-23): a ``sha`` that is not the head at request time is a 422
  (the docs name no code); a PR that is closed or a draft is a 400 with the message "Pull Request
  is not mergeable" (the docs say 400 for "not ready to merge, for example because it is closed",
  and name no draft case); ``merge_action: merge_queue`` on a base with no queue, and
  ``direct_merge`` on a base with one, are 400s; the default action is the queue where the base has
  one; a request that runs after the head moved, the base conflicts or a protection blocks ends as
  ``failed`` with a message the fake words itself; ``enqueued`` is what a queue request resolves to
  (final, per the docs), and the PR merges only when a test calls ``complete_queue``; the
  ``rebase`` method makes one commit on the base with the merged tree, not a replay of commits.
* Merge-queue and protection behaviour is scripted, not computed: ``enable_merge_queue``,
  ``block_merge`` (a message that a failing run carries), ``complete_queue`` and ``dequeue``.
  Check runs and rulesets belong to D4-20.
* ``mergeable`` and ``mergeable_state`` are null and ``unknown`` on a PR's first read after it is
  created or either branch moves, and computed on the next one (documented as asynchronous).
  ``mergeable_state`` takes the values ``dirty``, ``draft``, ``behind``, ``blocked`` and ``clean``
  and no others; real GitHub has more (unsourced limit).
* Marking a draft ready is GraphQL on GitHub (``markPullRequestReadyForReview``); the fake offers
  ``mark_ready`` as a stand-in and the REST edit ignores ``draft``, as the docs list no such field.
* ``POST /merges`` fast-forwards the base when it is an ancestor of the head (201, the head
  commit), and answers 204 when the head is already in the base (documented). The fast forward is
  unsourced. A conflict is 409 "Merge conflict" (documented 409).
* ``PUT .../update-branch`` checks ``expected_head_sha`` and a conflict at request time (both 422,
  unsourced for the conflict) and applies at ``settle()``, as it is a background job on GitHub.
* Trees are flat (path to blob, no sub-trees, no symlinks or sub-modules), and merges are
  three-way per file; there are no author, committer, signature or ``verified`` fields.
* ``mergeable_state`` aside, pull request, commit and ref bodies carry a subset of GitHub's
  fields: the ones an adapter reads. No ``node_id`` and no ``_links``.
* Comments list oldest first (documented: ascending by ID). ``order = "newest_first"`` reverses
  that for the conformance suite's look-up-order test; GitHub offers no such switch, so a correct
  adapter must not depend on either order. Paging is GitHub's page-number paging with a ``link``
  header (the issues route puts a cursor in it for some lists; the comments route is not known
  to, unsourced).
* The 403 for a missing permission ("Resource not accessible by integration") and the 422
  texts for refs, trees, commits and field types are GitHub's wording from observation, not
  from a docs page. The permission map is ours: refs, blobs, trees, commits, merges and
  update-branch need ``contents``; pulls and merge-async need ``pull_requests``; comments need
  ``issues`` or ``pull_requests``.
* Not modelled: reviews, check runs, labels, assignees, ``expand``-style options, GraphQL, and
  webhooks (the sender is ``fakes.github.webhooks``; nothing here sends one on a state change).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json as jsonlib
import re
import uuid as uuidlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from fakes.github.auth.server import (
    HOST,
    INSTALLATION_ID,
    INSTALLATION_OWNER,
    INSTALLATION_REPOS,
    PRINCIPAL,
    FakeGitHubAuth,
    Response,
    _iso,
    _page_number,
    _per_page,
)

OWNER = INSTALLATION_OWNER
REPO = f"{OWNER}/{INSTALLATION_REPOS[0]}"  # "acme/app"
RESULT_TTL = (
    24 * 3600.0
)  # seconds; https://docs.github.com/en/rest/pulls/pulls#get-the-result-of-an-asynchronous-merge
DOCS = "https://docs.github.com/en/rest"
SOURCES: Mapping[str, str] = {
    "get-pull": f"{DOCS}/pulls/pulls#get-a-pull-request",
    "list-pulls": f"{DOCS}/pulls/pulls#list-pull-requests",
    "create-pull": f"{DOCS}/pulls/pulls#create-a-pull-request",
    "update-pull": f"{DOCS}/pulls/pulls#update-a-pull-request",
    "update-branch": f"{DOCS}/pulls/pulls#update-a-pull-request-branch",
    "merge-async": f"{DOCS}/pulls/pulls#merge-a-pull-request-asynchronously",
    "merge-async-result": f"{DOCS}/pulls/pulls#get-the-result-of-an-asynchronous-merge",
    "list-comments": f"{DOCS}/issues/comments#list-issue-comments",
    "create-comment": f"{DOCS}/issues/comments#create-an-issue-comment",
    "get-ref": f"{DOCS}/git/refs#get-a-reference",
    "create-ref": f"{DOCS}/git/refs#create-a-reference",
    "update-ref": f"{DOCS}/git/refs#update-a-reference",
    "delete-ref": f"{DOCS}/git/refs#delete-a-reference",
    "create-blob": f"{DOCS}/git/blobs#create-a-blob",
    "create-tree": f"{DOCS}/git/trees#create-a-tree",
    "create-commit": f"{DOCS}/git/commits#create-a-commit",
    "get-commit": f"{DOCS}/git/commits#get-a-commit-object",
    "merge-branch": f"{DOCS}/branches/branches#merge-a-branch",
}
# Every route has a page. Behaviours inside a route that no page documents are named above and
# marked "unsourced" where they are implemented.
UNSOURCED: frozenset[str] = frozenset()

_MODES = {"100644", "100755", "040000", "160000", "120000"}
_METHODS = ("merge", "squash", "rebase")
_ACTIONS = ("default", "direct_merge", "merge_queue")
_LEVELS = {"read": 1, "write": 2, "admin": 3}
_NOT_MERGEABLE = "Pull Request is not mergeable"


def _sha(*parts: object) -> str:
    return hashlib.sha1(jsonlib.dumps(parts, sort_keys=True).encode()).hexdigest()  # noqa: S324


@dataclass
class Commit:
    sha: str
    parents: tuple[str, ...]
    tree: str
    message: str
    depth: int


@dataclass
class Comment:
    id: int
    number: int
    author: str
    body: str
    created: float


@dataclass
class Pull:
    number: int
    title: str
    body: str
    head: str
    base: str
    user: str
    created: float
    draft: bool = False
    state: str = "open"
    merged: bool = False
    merge_commit_sha: str | None = None
    closed_at: float | None = None
    merged_at: float | None = None
    updated: float = 0.0
    computed: bool = False
    blocked: str | None = None
    queued: bool = False


@dataclass
class MergeRequest:
    uuid: str
    number: int
    expected_head: str
    method: str
    action: str  # as requested ("default" included)
    effective: str  # what it resolves to: direct_merge or merge_queue
    bypass: bool
    commit_title: str | None
    status: str = "pending"
    message: str = ""
    sha: str | None = None
    polls: int = 0
    updated: float = 0.0


@dataclass
class Repo:
    commits: dict[str, Commit] = field(default_factory=dict)
    trees: dict[str, dict[str, str]] = field(default_factory=dict)  # tree -> {path: blob sha}
    blobs: dict[str, str] = field(default_factory=dict)
    refs: dict[str, str] = field(default_factory=dict)  # "refs/heads/main" -> commit sha
    pulls: list[Pull] = field(default_factory=list)
    comments: list[Comment] = field(default_factory=list)
    queues: set[str] = field(default_factory=set)  # base branches with a merge queue
    requests: dict[str, MergeRequest] = field(default_factory=dict)
    updates: list[tuple[int, str]] = field(default_factory=list)  # (PR number, expected head)


@dataclass
class _Call:
    repo: Repo
    full: str
    match: re.Match[str]
    body: dict[str, Any]
    query: Mapping[str, str]
    quota: dict[str, str]
    number: int = 0


def _ok(status: int, body: Any, quota: Mapping[str, str], **headers: str) -> Response:
    return Response(status, {**quota, **headers}, body)


def _err(status: int, message: str, quota: Mapping[str, str], **extra: Any) -> Response:
    return Response(status, dict(quota), {"message": message, **extra})


def _invalid(field_name: str, why: str, quota: Mapping[str, str]) -> Response:
    # unsourced wording: GitHub's "Invalid request" message for a wrongly typed property
    message = f"Invalid request.\n\nFor 'properties/{field_name}', {why}."
    return Response(422, dict(quota), {"message": message})


def _validation(
    quota: Mapping[str, str], resource: str, field_name: str, code: str, message: str = ""
) -> Response:
    error: dict[str, str] = {"resource": resource, "field": field_name, "code": code}
    if message:
        error["message"] = message
    return Response(422, dict(quota), {"message": "Validation Failed", "errors": [error]})


class FakeGitHubPulls(FakeGitHubAuth):
    """Pull requests, comments, refs, commits and merges over the fake GitHub's auth and limits."""

    ROUTE_NAMES = frozenset(SOURCES) | UNSOURCED

    def __init__(self) -> None:
        super().__init__()
        self.repos: dict[str, Repo] = {
            f"{OWNER}/{name}": self._new_repo() for name in INSTALLATION_REPOS
        }
        self.order = "oldest_first"  # documented: ascending by ID
        self.pending_polls = 1
        self.log: list[tuple[str, str]] = []
        self._cid = 100
        self._swallowed = -1

    # --- setup and test controls (the fake's own view; an adapter has no such call) ------------

    def mint(
        self,
        repositories: Sequence[str] | None = None,
        permissions: Mapping[str, str] | None = None,
    ) -> str:
        """An installation token, as an adapter would hold one."""
        r = self.create_installation_token(
            self.app_jwt(), INSTALLATION_ID, repositories, permissions
        )
        assert r.status == 201, r.body
        return str(r.body["token"])

    @staticmethod
    def _new_repo() -> Repo:
        repo = Repo()
        blob = _sha("blob", "hello")
        repo.blobs[blob] = "hello"
        tree = _sha("tree", {"README.md": blob})
        repo.trees[tree] = {"README.md": blob}
        root = Commit(_sha("commit", tree, [], "initial", 0), (), tree, "initial", 1)
        repo.commits[root.sha] = root
        repo.refs["refs/heads/main"] = root.sha
        return repo

    def sha(self, repo: str, branch: str) -> str | None:
        return self.repos[repo].refs.get(f"refs/heads/{branch}")

    def files(self, tree: str, repo: str = REPO) -> dict[str, str]:
        r = self.repos[repo]
        return {path: r.blobs[b] for path, b in r.trees[tree].items()}

    def tree_of(self, commit: str, repo: str = REPO) -> str:
        return self.repos[repo].commits[commit].tree

    def pulls(self, repo: str) -> list[Pull]:
        return self.repos[repo].pulls

    def push(
        self, repo: str, branch: str, files: Mapping[str, str | None], message: str = "push"
    ) -> str:
        """Someone pushes one commit to ``branch`` (created from ``main`` if new): ``files`` maps
        a path to its content, or to None to delete it. Moves PRs on that branch."""
        r = self.repos[repo]
        ref = f"refs/heads/{branch}"
        tip = r.refs.get(ref) or r.refs["refs/heads/main"]
        tree = dict(r.trees[r.commits[tip].tree])
        for path, content in files.items():
            if content is None:
                tree.pop(path, None)
            else:
                tree[path] = self._blob(r, content)
        commit = self._commit(r, tree, (tip,), message)
        r.refs[ref] = commit.sha
        self._moved(r, ref)
        return commit.sha

    def mark_ready(self, number: int, repo: str = REPO) -> None:
        """Stand-in for GraphQL ``markPullRequestReadyForReview``."""
        self._pull(self.repos[repo], number).draft = False
        self._touch(self.repos[repo], number)

    def block_merge(self, number: int, message: str | None, repo: str = REPO) -> None:
        """A protection that stops the merge when it RUNS (None lifts it)."""
        self._pull(self.repos[repo], number).blocked = message

    def enable_merge_queue(self, repo: str, branch: str) -> None:
        self.repos[repo].queues.add(branch)

    def complete_queue(self, number: int, repo: str = REPO) -> None:
        """The queue merges the PR."""
        r = self.repos[repo]
        pr = self._pull(r, number)
        assert pr.queued, "the pull request is not in a queue"
        pr.queued = False
        merged = self._do_merge(r, pr, "merge", None)
        assert isinstance(merged, str), merged

    def dequeue(self, number: int, repo: str = REPO) -> None:
        self._pull(self.repos[repo], number).queued = False

    def add_comment(
        self, number: int, author: str, body: str, *, older: bool = False, repo: str = REPO
    ) -> Comment:
        r = self.repos[repo]
        self._cid += 1
        comment = Comment(self._cid, number, author, body, self.now)
        r.comments.insert(0, comment) if older else r.comments.append(comment)
        return comment

    def settle(self) -> None:
        """Run every pending merge request and update-branch job now."""
        for r in self.repos.values():
            for req in list(r.requests.values()):
                if req.status == "pending":
                    self._run(r, req)
            for number, expected in r.updates:
                pr = self._pull(r, number)
                if r.refs.get(f"refs/heads/{pr.head}") == expected and pr.state == "open":
                    self._merge_into(
                        r,
                        pr.head,
                        r.refs[f"refs/heads/{pr.base}"],
                        f"Merge branch '{pr.base}' into {pr.head}",
                    )
            r.updates.clear()

    def edit_pull(self, number: int, repo: str = REPO, **fields: str) -> None:
        """Someone edits the PR's ``title`` or ``body`` outside the adapter (a human in the UI)."""
        pr = self._pull(self.repos[repo], number)
        for name, value in fields.items():
            if name not in ("title", "body"):
                raise AssertionError(f"edit_pull cannot set {name!r}")
            setattr(pr, name, value)
        pr.updated = self.now

    def handle(self, op: str, token: str, **kw: Any) -> Response:
        """The auth fake's stand-in ops (``read``, ``lookup``, ``write``) are gone: this fake has
        the real routes, and an adapter or harness must use ``request``."""
        raise AssertionError(f"FakeGitHubPulls has real routes: use request(), not handle({op!r})")

    # --- the Git object model -------------------------------------------------------------------

    @staticmethod
    def _blob(r: Repo, content: str) -> str:
        sha = _sha("blob", content)
        r.blobs[sha] = content
        return sha

    @staticmethod
    def _tree(r: Repo, entries: Mapping[str, str]) -> str:
        sha = _sha("tree", dict(entries))
        r.trees[sha] = dict(entries)
        return sha

    def _commit(
        self, r: Repo, tree_entries: Mapping[str, str], parents: tuple[str, ...], message: str
    ) -> Commit:
        tree = self._tree(r, tree_entries)
        depth = 1 + max((r.commits[p].depth for p in parents), default=0)
        sha = _sha("commit", tree, list(parents), message, len(r.commits), self.now)
        commit = Commit(sha, parents, tree, message, depth)
        r.commits[sha] = commit
        return commit

    @staticmethod
    def _ancestors(r: Repo, sha: str) -> set[str]:
        seen: set[str] = set()
        todo = [sha]
        while todo:
            current = todo.pop()
            if current not in seen:
                seen.add(current)
                todo.extend(r.commits[current].parents)
        return seen

    def _merge_base(self, r: Repo, a: str, b: str) -> str:
        common = self._ancestors(r, a) & self._ancestors(r, b)
        return max(common, key=lambda s: r.commits[s].depth)

    def _three_way(self, r: Repo, ours: str, theirs: str) -> dict[str, str] | None:
        """The merged tree of two commits, or None on a conflict (both changed one path
        differently since their merge base)."""
        base = r.trees[r.commits[self._merge_base(r, ours, theirs)].tree]
        o, t = r.trees[r.commits[ours].tree], r.trees[r.commits[theirs].tree]
        merged: dict[str, str] = {}
        for path in set(base) | set(o) | set(t):
            b, x, y = base.get(path), o.get(path), t.get(path)
            if x == y or y == b:
                chosen = x
            elif x == b:
                chosen = y
            else:
                return None
            if chosen is not None:
                merged[path] = chosen
        return merged

    def _moved(self, r: Repo, ref: str) -> None:
        """A branch moved: every open PR on it must be re-evaluated by GitHub."""
        name = ref.removeprefix("refs/heads/")
        for pr in r.pulls:
            if name in (pr.head, pr.base):
                pr.computed = False
                pr.updated = self.now

    def _merge_into(self, r: Repo, base: str, h: str, message: str) -> Commit | None | str:
        """Merge commit ``h`` into branch ``base``: the commit, None if there is nothing to
        merge, or "conflict"."""
        b = r.refs[f"refs/heads/{base}"]
        if h in self._ancestors(r, b):
            return None
        if b in self._ancestors(r, h):
            commit = r.commits[h]
        else:
            tree = self._three_way(r, b, h)
            if tree is None:
                return "conflict"
            commit = self._commit(r, tree, (b, h), message)
        r.refs[f"refs/heads/{base}"] = commit.sha
        self._moved(r, f"refs/heads/{base}")
        return commit

    # --- pull request state ---------------------------------------------------------------------

    @staticmethod
    def _pull(r: Repo, number: int) -> Pull:
        for pr in r.pulls:
            if pr.number == number:
                return pr
        raise KeyError(number)

    def _touch(self, r: Repo, number: int) -> None:
        self._pull(r, number).updated = self.now

    def _conflicts(self, r: Repo, pr: Pull) -> bool:
        return (
            self._three_way(r, r.refs[f"refs/heads/{pr.base}"], r.refs[f"refs/heads/{pr.head}"])
            is None
        )

    def _pr_json(self, r: Repo, full: str, pr: Pull) -> dict[str, Any]:
        head, base = (
            r.refs.get(f"refs/heads/{pr.head}", ""),
            r.refs.get(f"refs/heads/{pr.base}", ""),
        )
        mergeable: bool | None = None
        state = "draft" if pr.draft else "unknown"
        if pr.state == "open" and not pr.merged and pr.computed:
            if self._conflicts(r, pr):
                mergeable, state = False, "dirty"
            else:
                mergeable = True
                if pr.draft:
                    state = "draft"
                elif base not in self._ancestors(r, head):
                    state = "behind"
                elif pr.blocked:
                    state = "blocked"
                else:
                    state = "clean"
        owner = full.split("/")[0]
        return {
            "url": f"{HOST}/repos/{full}/pulls/{pr.number}",
            "html_url": f"https://github.test/{full}/pull/{pr.number}",
            "number": pr.number,
            "state": pr.state,
            "title": pr.title,
            "body": pr.body,
            "user": {"login": pr.user},
            "draft": pr.draft,
            "merged": pr.merged,
            "merge_commit_sha": pr.merge_commit_sha,
            "mergeable": mergeable,
            "mergeable_state": state,
            "created_at": _iso(pr.created),
            "updated_at": _iso(pr.updated),
            "closed_at": None if pr.closed_at is None else _iso(pr.closed_at),
            "merged_at": None if pr.merged_at is None else _iso(pr.merged_at),
            "head": {"label": f"{owner}:{pr.head}", "ref": pr.head, "sha": head},
            "base": {"label": f"{owner}:{pr.base}", "ref": pr.base, "sha": base},
        }

    # --- the async merge ------------------------------------------------------------------------

    def _do_merge(self, r: Repo, pr: Pull, method: str, title: str | None) -> str:
        """Merge the PR into its base now: the merge commit SHA, or the failure message."""
        base_ref, head_ref = f"refs/heads/{pr.base}", f"refs/heads/{pr.head}"
        b, h = r.refs[base_ref], r.refs[head_ref]
        tree = self._three_way(r, b, h)
        if tree is None:
            return "Merge conflict between the base and the head."
        parents = (b, h) if method == "merge" else (b,)
        commit = self._commit(r, tree, parents, title or pr.title)
        r.refs[base_ref] = commit.sha
        pr.merged, pr.state = True, "closed"
        pr.merge_commit_sha, pr.merged_at, pr.closed_at = commit.sha, self.now, self.now
        self._moved(r, base_ref)
        return commit.sha

    def _run(self, r: Repo, req: MergeRequest) -> None:
        pr = self._pull(r, req.number)
        head = r.refs.get(f"refs/heads/{pr.head}")
        if pr.state != "open":
            self._finish(req, "failed", "The pull request is no longer open.")
        elif head != req.expected_head:
            # Docs: a push between request and run cancels the merge. The wording is unsourced.
            self._finish(
                req,
                "failed",
                "Merge cancelled: the head branch changed after the merge was requested.",
            )
        elif pr.blocked and not req.bypass:
            self._finish(req, "failed", pr.blocked)
        elif req.effective == "merge_queue":
            pr.queued = True
            self._finish(req, "enqueued", "The pull request was added to the merge queue.")
        else:
            result = self._do_merge(r, pr, req.method, req.commit_title)
            if re.fullmatch(r"[0-9a-f]{40}", result):
                self._finish(req, "merged", "The pull request was merged.", result)
            else:
                self._finish(req, "failed", result)

    def _finish(self, req: MergeRequest, status: str, message: str, sha: str | None = None) -> None:
        req.status, req.message, req.sha, req.updated = status, message, sha, self.now

    def _result(self, req: MergeRequest) -> dict[str, Any]:
        if req.status == "pending":
            details: dict[str, Any] = {
                "message": "The merge is pending.",
                "uuid": req.uuid,
                "merge_method": req.method,
                "merge_action": req.action,
                "expected_head_sha": req.expected_head,
                "bypass_rules": req.bypass,
            }
        elif req.status == "merged":
            details = {"message": req.message, "sha": req.sha}
        else:
            details = {"message": req.message}
        return {"status": req.status, "details": details}

    # --- the API --------------------------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        token: str,
        *,
        json: Any = None,
        query: Mapping[str, str] | None = None,
    ) -> Response:
        """One authenticated request, ``path`` as GitHub writes it (``/repos/{o}/{r}/...``). A
        body, if any, goes in ``json`` and query parameters (strings) in ``query``."""
        self.log.append((method, path))
        found = self._route(method, path)
        op = found[0] if found else "unrouted"
        page = _page_number((query or {}).get("page", 1)) if op == "lookup" else None
        early = self._preflight(op, self._token_refusal(token), page, metered=True)
        if early is not None:
            return early[0]
        quota = self._quota()
        if found is None:
            return _err(404, "Not Found", quota)
        op, name, perms, call = found
        grant = self._tokens[token]
        if not self._reaches(grant, call.full):
            return _err(404, "Not Found", quota)
        if not self._permitted(grant.permissions, perms):
            return _err(403, "Resource not accessible by integration", quota)
        call.quota, call.query = quota, dict(query or {})
        call.body = json if isinstance(json, dict) else {}
        out = getattr(self, "_h_" + name.replace("-", "_"))(call)
        if self._lose and method != "GET":
            self._lose = False
            raise TimeoutError("response lost")
        assert isinstance(out, Response)
        return out

    @staticmethod
    def _permitted(held: Mapping[str, str], needed: tuple[tuple[str, str], ...]) -> bool:
        """Every row of ``needed`` is ``(permission or "a|b", level)``; "a|b" is either of two."""
        for names, level in needed:
            best = max((_LEVELS.get(held.get(n, ""), 0) for n in names.split("|")), default=0)
            if best < _LEVELS[level]:
                return False
        return True

    def _route(
        self, method: str, path: str
    ) -> tuple[str, str, tuple[tuple[str, str], ...], _Call] | None:
        outer = re.fullmatch(r"/repos/([^/]+)/([^/]+)(/.*)", path)
        if outer is None:
            return None
        full = f"{outer[1]}/{outer[2]}".lower()
        for verb, pattern, op, name, perms in self._ROUTES:
            inner = re.fullmatch(pattern, outer[3])
            if verb == method and inner is not None:
                repo = self.repos.get(full)
                call = _Call(repo or Repo(), full, inner, {}, {}, {})
                return op, name, perms, call
        return None

    @staticmethod
    def _reaches(grant: Any, full: str) -> bool:
        owner, _, name = full.partition("/")
        return (
            owner == OWNER.lower()
            and name in INSTALLATION_REPOS
            and (grant.repositories is None or name in grant.repositories)
        )

    # Route table: (method, pattern, op, name, permissions)
    _PULLS = (("pull_requests", "read"),)
    _PULLS_W = (("pull_requests", "write"),)
    _GIT = (("contents", "read"),)
    _GIT_W = (("contents", "write"),)
    # (method, pattern after /repos/{o}/{r}, op the faults and counters know it by, name, needs)
    _ROUTES: Sequence[tuple[str, str, str, str, tuple[tuple[str, str], ...]]] = (
        ("GET", r"/pulls/(\d+)", "read", "get-pull", _PULLS),
        ("GET", r"/pulls", "list-pulls", "list-pulls", _PULLS),
        ("POST", r"/pulls", "create-pull", "create-pull", _PULLS_W),
        ("PATCH", r"/pulls/(\d+)", "update-pull", "update-pull", _PULLS_W),
        ("PUT", r"/pulls/(\d+)/update-branch", "update-branch", "update-branch", _PULLS_W + _GIT_W),
        ("PUT", r"/pulls/(\d+)/merge-async", "merge-async", "merge-async", _PULLS_W + _GIT_W),
        (
            "GET",
            r"/pulls/(\d+)/merge-async/([^/]+)",
            "merge-async-result",
            "merge-async-result",
            _PULLS,
        ),
        (
            "GET",
            r"/issues/(\d+)/comments",
            "lookup",
            "list-comments",
            (("issues|pull_requests", "read"),),
        ),
        (
            "POST",
            r"/issues/(\d+)/comments",
            "write",
            "create-comment",
            (("issues|pull_requests", "write"),),
        ),
        ("GET", r"/git/ref/(.+)", "get-ref", "get-ref", _GIT),
        ("POST", r"/git/refs", "create-ref", "create-ref", _GIT_W),
        ("PATCH", r"/git/refs/(.+)", "update-ref", "update-ref", _GIT_W),
        ("DELETE", r"/git/refs/(.+)", "delete-ref", "delete-ref", _GIT_W),
        ("POST", r"/git/blobs", "create-blob", "create-blob", _GIT_W),
        ("POST", r"/git/trees", "create-tree", "create-tree", _GIT_W),
        ("POST", r"/git/commits", "create-commit", "create-commit", _GIT_W),
        ("GET", r"/git/commits/([0-9a-fA-F]+)", "get-commit", "get-commit", _GIT),
        ("POST", r"/merges", "merge-branch", "merge-branch", _GIT_W),
    )

    # --- handlers: pull requests ------------------------------

    def _find_pull(self, c: _Call, group: int = 1) -> Pull | Response:
        try:
            return self._pull(c.repo, int(c.match[group]))
        except KeyError:
            return _err(404, "Not Found", c.quota)

    def _h_get_pull(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        body = self._pr_json(c.repo, c.full, pr)
        pr.computed = True  # the next read has the answer
        return _ok(200, body, c.quota)

    def _h_list_pulls(self, c: _Call) -> Response:
        state = c.query.get("state", "open")
        if state not in ("open", "closed", "all"):
            return _validation(c.quota, "PullRequest", "state", "invalid")
        direction = c.query.get("direction", "desc")
        if direction not in ("asc", "desc"):
            return _validation(c.quota, "PullRequest", "direction", "invalid")
        head = c.query.get("head")
        rows = [
            p
            for p in c.repo.pulls
            if (state == "all" or p.state == state)
            and (head is None or head == f"{c.full.split('/')[0]}:{p.head}")
            and ("base" not in c.query or c.query["base"] == p.base)
        ]
        rows.sort(key=lambda p: p.number, reverse=direction == "desc")
        chunk, headers = self._paginate(rows, c, f"/repos/{c.full}/pulls")
        return _ok(200, [self._pr_json(c.repo, c.full, p) for p in chunk], c.quota, **headers)

    def _paginate(
        self, rows: Sequence[Any], c: _Call, route: str
    ) -> tuple[list[Any], dict[str, str]]:
        """https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api"""
        page = _page_number(c.query.get("page", 1))
        per = _per_page(c.query.get("per_page", 30))
        chunk = list(rows[(page - 1) * per : page * per])
        last = max(1, -(-len(rows) // per))

        def url(number: int, rel: str) -> str:
            return f'<{HOST}{route}?page={number}&per_page={per}>; rel="{rel}"'

        links = ([url(page - 1, "prev"), url(1, "first")] if page > 1 and chunk else []) + (
            [url(page + 1, "next"), url(last, "last")] if len(rows) > page * per else []
        )
        return chunk, ({"link": ", ".join(links)} if links else {})

    def _h_create_pull(self, c: _Call) -> Response:
        b, q = c.body, c.quota
        for name in ("title", "head", "base"):
            if name not in b:
                return _invalid(name, "nil is not a string", q)
            if not isinstance(b[name], str):
                return _invalid(name, f"{b[name]!r} is not a string", q)
        if "body" in b and b["body"] is not None and not isinstance(b["body"], str):
            return _invalid("body", f"{b['body']!r} is not a string", q)
        if "draft" in b and not isinstance(b["draft"], bool):
            return _invalid("draft", f"{b['draft']!r} is not a boolean", q)
        head = str(b["head"]).split(":")[-1]
        refs = c.repo.refs
        if f"refs/heads/{head}" not in refs:
            return _validation(q, "PullRequest", "head", "invalid")
        if f"refs/heads/{b['base']}" not in refs:
            return _validation(q, "PullRequest", "base", "invalid")
        if any(p.state == "open" and (p.head, p.base) == (head, b["base"]) for p in c.repo.pulls):
            # unsourced wording
            message = f"A pull request already exists for {c.full.split('/')[0]}:{head}."
            return _validation(q, "PullRequest", "", "custom", message)
        if refs[f"refs/heads/{head}"] in self._ancestors(c.repo, refs[f"refs/heads/{b['base']}"]):
            return _validation(
                q, "PullRequest", "", "custom", f"No commits between {b['base']} and {head}"
            )
        number = 1 + max((p.number for p in c.repo.pulls), default=0)
        pr = Pull(
            number, b["title"], b.get("body") or "", head, b["base"], PRINCIPAL, self.now,
            draft=bool(b.get("draft", False)), updated=self.now,
        )  # fmt: skip
        c.repo.pulls.append(pr)
        return _ok(201, self._pr_json(c.repo, c.full, pr), q)

    def _h_update_pull(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        b, q = c.body, c.quota
        for name in ("title", "body", "state", "base"):
            if name in b and not isinstance(b[name], str):
                return _invalid(name, f"{b[name]!r} is not a string", q)
        if "state" in b and b["state"] not in ("open", "closed"):
            return _invalid("state", f"{b['state']!r} is not one of ['open', 'closed']", q)
        if "base" in b and f"refs/heads/{b['base']}" not in c.repo.refs:
            return _validation(q, "PullRequest", "base", "invalid")
        if b.get("state") == "open" and pr.merged:
            return _validation(
                q, "PullRequest", "state", "custom", "Pull request is already merged."
            )
        # ``draft`` is not a field of this route: ignored (documented fields only).
        if "title" in b:
            pr.title = b["title"]
        if "body" in b:
            pr.body = b["body"]
        if "base" in b and b["base"] != pr.base:
            pr.base, pr.computed = b["base"], False
        if b.get("state") == "closed" and pr.state == "open":
            pr.state, pr.closed_at = "closed", self.now
        elif b.get("state") == "open" and pr.state == "closed":
            pr.state, pr.closed_at = "open", None
        pr.updated = self.now
        return _ok(200, self._pr_json(c.repo, c.full, pr), q)

    def _h_update_branch(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        expected = c.body.get("expected_head_sha")
        if expected is not None and not isinstance(expected, str):
            return _invalid("expected_head_sha", f"{expected!r} is not a string", c.quota)
        head = c.repo.refs[f"refs/heads/{pr.head}"]
        if expected is not None and expected != head:
            return _validation(
                c.quota, "PullRequest", "expected_head_sha", "custom",
                "expected head sha didn't match current head ref.",
            )  # fmt: skip
        if pr.state != "open" or self._conflicts(c.repo, pr):
            return _validation(
                c.quota, "PullRequest", "", "custom", "merge conflict between base and head"
            )
        c.repo.updates.append((pr.number, head))
        url = f"https://github.test/{c.full}/pull/{pr.number}"
        return _ok(202, {"message": "Updating pull request branch.", "url": url}, c.quota)

    @staticmethod
    def _uuid(c: _Call, number: int) -> str:
        seed = f"{c.full}/{number}/{len(c.repo.requests)}"
        return str(uuidlib.uuid5(uuidlib.NAMESPACE_URL, seed))

    def _h_merge_async(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        b, q = c.body, c.quota
        checks: tuple[tuple[str, type | tuple[type, ...]], ...] = (
            ("sha", str), ("commit_title", str), ("commit_message", str), ("bypass_rules", bool),
        )  # fmt: skip
        for name, kind in checks:
            if name in b and not isinstance(b[name], kind):
                word = "a boolean" if kind is bool else "a string"
                return _invalid(name, f"{b[name]!r} is not {word}", q)
        for name, allowed in (("merge_method", _METHODS), ("merge_action", _ACTIONS)):
            if name in b and b[name] not in allowed:
                return _invalid(name, f"{b[name]!r} is not one of {list(allowed)}", q)
        method, action = b.get("merge_method", "merge"), b.get("merge_action", "default")
        live = [x for x in c.repo.requests.values() if x.number == pr.number]
        if pr.merged:
            done = next((x for x in reversed(live) if x.status == "merged"), None)
            sha = done.sha if done else pr.merge_commit_sha
            return _ok(
                200, {"status": "merged", "details": {"message": "Already merged.", "sha": sha}}, q
            )
        if pr.queued:
            return _ok(
                200, {"status": "enqueued", "details": {"message": "Already in a merge queue."}}, q
            )
        pending = next((x for x in live if x.status == "pending"), None)
        if pending is not None:
            return Response(409, dict(q), self._result(pending))
        if pr.state != "open" or pr.draft:
            return _err(400, _NOT_MERGEABLE, q)
        queued_base = pr.base in c.repo.queues
        if (action == "merge_queue" and not queued_base) or (
            action == "direct_merge" and queued_base
        ):
            return _err(400, _NOT_MERGEABLE, q)
        head = c.repo.refs[f"refs/heads/{pr.head}"]
        if "sha" in b and b["sha"] != head:
            return _err(422, "Head branch was modified. Review and try the merge again.", q)
        effective = "merge_queue" if queued_base else "direct_merge"
        req = MergeRequest(
            self._uuid(c, pr.number),
            pr.number, head, method, action, effective, bool(b.get("bypass_rules", False)),
            b.get("commit_title"), updated=self.now,
        )  # fmt: skip
        c.repo.requests[req.uuid] = req
        return _ok(202, self._result(req), q)

    def _h_merge_async_result(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        req = c.repo.requests.get(c.match[2])
        if req is None or req.number != pr.number or self.now - req.updated >= RESULT_TTL:
            return _err(404, "Not Found", c.quota)
        if req.status == "pending":
            req.polls += 1
            if req.polls > self.pending_polls:
                self._run(c.repo, req)
        return _ok(200, self._result(req), c.quota)

    # --- handlers: comments ------------------------------

    def _h_list_comments(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        rows = [x for x in c.repo.comments if x.number == pr.number]
        if self.order == "newest_first":
            rows.reverse()
        chunk, headers = self._paginate(rows, c, f"/repos/{c.full}/issues/{pr.number}/comments")
        return _ok(200, [self._comment_json(c.full, x) for x in chunk], c.quota, **headers)

    def _h_create_comment(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        body = c.body.get("body")
        if body is None or not isinstance(body, str):
            return _invalid("body", f"{body!r} is not a string", c.quota)
        if not body.strip():
            return _validation(c.quota, "IssueComment", "body", "missing_field")
        if self.swallow > 0:  # answered success, not applied
            self.swallow -= 1
            ghost = Comment(self._swallowed, pr.number, PRINCIPAL, body, self.now)
            self._swallowed -= 1
            return _ok(201, self._comment_json(c.full, ghost), c.quota)
        return _ok(
            201,
            self._comment_json(c.full, self.add_comment(pr.number, PRINCIPAL, body, repo=c.full)),
            c.quota,
        )

    @staticmethod
    def _comment_json(full: str, x: Comment) -> dict[str, Any]:
        return {
            "id": x.id,
            "url": f"{HOST}/repos/{full}/issues/comments/{x.id}",
            "issue_url": f"{HOST}/repos/{full}/issues/{x.number}",
            "user": {"login": x.author},
            "body": x.body,
            "created_at": _iso(x.created),
            "updated_at": _iso(x.created),
        }

    # --- handlers: Git objects and refs ------------------------------

    def _h_create_blob(self, c: _Call) -> Response:
        content, encoding = c.body.get("content"), c.body.get("encoding", "utf-8")
        if not isinstance(content, str):
            return _invalid("content", f"{content!r} is not a string", c.quota)
        if encoding not in ("utf-8", "base64"):
            return _invalid("encoding", f"{encoding!r} is not one of ['utf-8', 'base64']", c.quota)
        if encoding == "base64":
            try:
                content = base64.b64decode(content, validate=True).decode()
            except (binascii.Error, UnicodeDecodeError):
                return _err(422, "Validation Failed", c.quota)
        sha = self._blob(c.repo, content)
        return _ok(201, {"sha": sha, "url": f"{HOST}/repos/{c.full}/git/blobs/{sha}"}, c.quota)

    def _h_create_tree(self, c: _Call) -> Response:
        q, r = c.quota, c.repo
        entries = c.body.get("tree")
        if not isinstance(entries, list):
            return _invalid("tree", f"{entries!r} is not an array", q)
        base = c.body.get("base_tree")
        if base is not None and (not isinstance(base, str) or base not in r.trees):
            return _validation(q, "Tree", "base_tree", "invalid")
        tree = dict(r.trees[base]) if base else {}
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get("path"), str) or not e["path"]:
                return _validation(q, "Tree", "path", "missing_field")
            if e.get("mode") not in _MODES or e.get("type") != "blob":
                return _validation(q, "Tree", "mode", "invalid")
            if ("content" in e) == ("sha" in e):
                return _validation(
                    q, "Tree", "sha", "missing_field", "give exactly one of sha and content"
                )
            if "content" in e:
                if not isinstance(e["content"], str):
                    return _invalid("content", f"{e['content']!r} is not a string", q)
                tree[e["path"]] = self._blob(r, e["content"])
            elif e["sha"] is None:
                tree.pop(e["path"], None)  # documented: null deletes the file (with a base tree)
            elif e["sha"] in r.blobs:
                tree[e["path"]] = e["sha"]
            else:
                return _validation(q, "Tree", "sha", "invalid")
        sha = self._tree(r, tree)
        return _ok(
            201, {"sha": sha, "url": f"{HOST}/repos/{c.full}/git/trees/{sha}", "tree": []}, q
        )

    def _commit_json(self, c: _Call, commit: Commit) -> dict[str, Any]:
        base = f"{HOST}/repos/{c.full}/git"
        return {
            "sha": commit.sha,
            "url": f"{base}/commits/{commit.sha}",
            "message": commit.message,
            "tree": {"sha": commit.tree, "url": f"{base}/trees/{commit.tree}"},
            "parents": [{"sha": p, "url": f"{base}/commits/{p}"} for p in commit.parents],
        }

    def _h_create_commit(self, c: _Call) -> Response:
        b, q, r = c.body, c.quota, c.repo
        if not isinstance(b.get("message"), str):
            return _invalid("message", f"{b.get('message')!r} is not a string", q)
        tree, parents = b.get("tree"), b.get("parents", [])
        if not isinstance(tree, str):
            return _invalid("tree", f"{tree!r} is not a string", q)
        if not isinstance(parents, list) or not all(isinstance(p, str) for p in parents):
            return _invalid("parents", f"{parents!r} is not an array of strings", q)
        if tree not in r.trees:
            return _validation(q, "Commit", "tree", "invalid")
        if any(p not in r.commits for p in parents):
            return _validation(q, "Commit", "parents", "invalid")
        depth = 1 + max((r.commits[p].depth for p in parents), default=0)
        sha = _sha("commit", tree, parents, b["message"], len(r.commits), self.now)
        commit = Commit(sha, tuple(parents), tree, b["message"], depth)
        r.commits[sha] = commit
        return _ok(201, self._commit_json(c, commit), q)

    def _h_get_commit(self, c: _Call) -> Response:
        commit = c.repo.commits.get(c.match[1].lower())
        if commit is None:
            return _err(404, "Not Found", c.quota)
        return _ok(200, self._commit_json(c, commit), c.quota)

    def _ref_json(self, c: _Call, ref: str) -> dict[str, Any]:
        sha = c.repo.refs[ref]
        return {
            "ref": ref,
            "url": f"{HOST}/repos/{c.full}/git/{ref}",
            "object": {
                "sha": sha,
                "type": "commit",
                "url": f"{HOST}/repos/{c.full}/git/commits/{sha}",
            },
        }

    def _h_get_ref(self, c: _Call) -> Response:
        ref = "refs/" + c.match[1]
        if ref not in c.repo.refs:
            return _err(404, "Not Found", c.quota)
        return _ok(200, self._ref_json(c, ref), c.quota)

    def _h_create_ref(self, c: _Call) -> Response:
        ref, sha, q = c.body.get("ref"), c.body.get("sha"), c.quota
        if not isinstance(ref, str):
            return _invalid("ref", f"{ref!r} is not a string", q)
        if not isinstance(sha, str):
            return _invalid("sha", f"{sha!r} is not a string", q)
        if not re.fullmatch(r"refs/[^/\s]+/\S+", ref):  # unsourced wording
            return _err(422, "Reference name is invalid", q)
        if sha not in c.repo.commits:
            return _err(422, "Object does not exist", q)
        if ref in c.repo.refs:
            return _err(422, "Reference already exists", q)
        c.repo.refs[ref] = sha
        self._moved(c.repo, ref)
        return _ok(201, self._ref_json(c, ref), q)

    def _h_update_ref(self, c: _Call) -> Response:
        ref, q = "refs/" + c.match[1], c.quota
        sha, force = c.body.get("sha"), c.body.get("force", False)
        if not isinstance(sha, str):
            return _invalid("sha", f"{sha!r} is not a string", q)
        if not isinstance(force, bool):
            return _invalid("force", f"{force!r} is not a boolean", q)
        if ref not in c.repo.refs:
            return _err(404, "Not Found", q)
        if sha not in c.repo.commits:
            return _err(422, "Object does not exist", q)
        if not force and c.repo.refs[ref] not in self._ancestors(c.repo, sha):
            return _err(422, "Update is not a fast forward", q)
        c.repo.refs[ref] = sha
        self._moved(c.repo, ref)
        return _ok(200, self._ref_json(c, ref), q)

    def _h_delete_ref(self, c: _Call) -> Response:
        ref = "refs/" + c.match[1]
        if ref not in c.repo.refs:
            return _err(422, "Reference does not exist", c.quota)
        del c.repo.refs[ref]
        self._moved(c.repo, ref)
        return _ok(204, None, c.quota)

    # --- handlers: POST /merges ------------------------------

    def _h_merge_branch(self, c: _Call) -> Response:
        b, q, r = c.body, c.quota, c.repo
        for name in ("base", "head"):
            if not isinstance(b.get(name), str):
                return _invalid(name, f"{b.get(name)!r} is not a string", q)
        if "commit_message" in b and not isinstance(b["commit_message"], str):
            return _invalid("commit_message", f"{b['commit_message']!r} is not a string", q)
        if f"refs/heads/{b['base']}" not in r.refs:
            return _err(404, "Base does not exist", q)  # unsourced wording
        head = r.refs.get(f"refs/heads/{b['head']}") or (
            b["head"] if b["head"] in r.commits else None
        )
        if head is None:  # a branch or a commit SHA is accepted as ``head`` (documented)
            return _err(404, "Head does not exist", q)
        message = b.get("commit_message") or f"Merge branch '{b['head']}' into {b['base']}"
        result = self._merge_into(r, b["base"], head, message)
        if result is None:
            return _ok(204, None, q)
        if isinstance(result, str):
            return _err(409, "Merge conflict", q)
        out = self._commit_json(c, result)
        out["commit"] = {"message": result.message, "tree": out["tree"]}
        return _ok(201, out, q)
