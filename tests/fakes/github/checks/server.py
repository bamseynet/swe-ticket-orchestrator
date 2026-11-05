"""An in-process fake of GitHub's check run, ruleset, review and workflow dispatch routes (D4-20).

This is a SERVER, not an adapter, and it holds no real credential: every ID, SHA and token is
synthetic. It EXTENDS D4-19's ``FakeGitHubPulls`` (so the PR, ref, commit and merge routes, the
auth, limits and faults of D4-16 are that fake's, unchanged) without editing ``pulls/``. The
composition is by subclassing: a PR's head SHA gets check runs; the rulesets that apply to its base
branch, with its check runs and reviews, decide the merge by setting ``Pull.blocked`` (the pulls
fake's own seam) whenever a PR is rendered or a merge request runs. ``block_merge`` still works and
wins. No hook in ``pulls/`` was needed.

Standard (as for the Jira fakes and D4-19): at least as strict as GitHub's REST docs where a wrong
adapter would otherwise pass (types, enums, required fields, who may update a check run, the
default-branch rule for dispatch), never stricter than documented GitHub on a correct adapter's path
(unknown body keys are ignored; ``conditions`` and the ``ref_name`` lists are optional). Each route
names its page in ``SOURCES``; every behaviour no page documents is in the list below, or says
"unsourced" where it is implemented. The live suite (D4-23, D12) proves all of it, and when they
disagree the fake is wrong.

What a merge guard can read. Protection failures give messages in the shape GitHub's rulesets use
(``Repository rule violations found`` and one line per failing rule). ``protection(number)`` gives
the same failures as ``Violation`` rows with a stable ``kind``, which is what a guard maps to an
explanation: ``check_expected`` (missing or pending: the docs call both "Expected"),
``check_failing``, ``not_up_to_date``, ``approvals_missing`` and ``changes_requested``.

Known departures, each deliberate:

* Rulesets only. Classic branch protection is a different API and is not modelled. Rules modelled:
  ``required_status_checks``, ``pull_request`` (approval count, changes requested, stale-review
  dismissal on push), ``creation``, ``update``, ``deletion``, ``non_fast_forward``; they are
  accepted by ``POST /rulesets`` and enforced. Other rule types are a 422 (unsourced: GitHub
  accepts more). Not enforced though accepted: ``require_code_owner_review``,
  ``require_last_push_approval``, ``required_review_thread_resolution``,
  ``required_linear_history``, ``required_signatures``, ``bypass_actors`` (bypass lists need an
  organization-owned repository, RESEARCH.md; ``bypass_rules`` on the merge request skips every
  block, as in the pulls fake), ``evaluate`` mode (counts nothing, as if disabled), the ``push``
  target, repository-property conditions and ``includes_parents``.
* Unsourced wording: every protection message, the 422 for a duplicate ruleset name, the messages
  of rule-blocked ref changes and ``POST /merges``, "Can not approve your own pull request",
  "No commit found for SHA", "No ref found for" and the dispatch input errors. Unsourced behaviour:
  a ruleset with no ``conditions`` applies to nothing; ``*`` in a ref pattern stops at ``/`` and
  ``**`` does not, ``~DEFAULT_BRANCH`` and ``~ALL`` are as documented, and a pattern without
  ``refs/`` is taken as a branch name; a rule-blocked ``POST /merges`` is a 409; the 403 for
  updating another App's check run; check runs list oldest first; ``latest`` means the highest ID
  per (App, name); runs list newest first.
* Check runs: no annotations, images, ``actions`` buttons or check suites; ``rerequest`` is not
  modelled. A required check passes on ``success``, ``neutral`` or ``skipped`` (documented:
  about-status-checks) and fails on the other conclusions. Required contexts are matched against
  check run names only; commit statuses are not modelled.
* Reviews: ``comments`` on a review are ignored; there is no review thread model. Only reviews by
  people with write access count (``add_review(..., writer=False)`` makes one that does not).
  Approvals older than the head are dismissed at push time only when a ``pull_request`` rule says
  ``dismiss_stale_reviews_on_push``. The App itself cannot approve or request changes on a PR it
  opened. A PR is opened by this fake's principal; ``set_author`` makes it someone else's.
* Dispatch: the workflow file must exist on the default branch (documented, events-that-trigger-
  workflows) and its content AT THE REF decides the trigger and inputs (YAML subset: ``on``,
  ``workflow_dispatch.inputs`` with ``required``, ``default`` and ``options``, ``jobs`` keys and
  names). The 204 answer is the classic one; ``return_run_details: true`` in the BODY gives 200 and
  ``workflow_run_id``, ``run_url`` and ``html_url`` (the docs show the response keys; that the
  option is a body field is unsourced). A run's ID is returned only there: a lost response (fault
  mode ``lose``, op ``dispatch``) leaves the run and nothing that names it; recover by listing
  runs with ``event=workflow_dispatch`` and ``head_sha``. A dispatch is not idempotent. Each job of
  the workflow becomes a check run under the GitHub Actions app when the run starts; a test moves
  runs on with ``start_run`` and ``complete_run`` (GitHub gives no such controls).
* This fake's installation also holds ``actions`` and ``administration`` write, which the auth
  fake's does not list: the real App's set is D4-24's, and a token asking for more is a 422.
* Check run, ruleset, review and run bodies carry the fields an adapter reads, not all of GitHub's
  (no ``node_id``, ``_links``, ``check_suite`` beyond an ID, or job-level run APIs).
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import yaml

from fakes.github.auth.server import APP_ID, HOST, PRINCIPAL, Response, _iso
from fakes.github.pulls.server import (
    OWNER,
    REPO,
    FakeGitHubPulls,
    MergeRequest,
    Pull,
    Repo,
    _Call,
    _err,
    _invalid,
    _ok,
    _validation,
)
from fakes.github.pulls.server import SOURCES as PULLS_SOURCES

DOCS = "https://docs.github.com/en/rest"
SOURCES: Mapping[str, str] = {
    "create-check-run": f"{DOCS}/checks/runs#create-a-check-run",
    "update-check-run": f"{DOCS}/checks/runs#update-a-check-run",
    "get-check-run": f"{DOCS}/checks/runs#get-a-check-run",
    "list-check-runs-for-ref": f"{DOCS}/checks/runs#list-check-runs-for-a-git-reference",
    "list-rulesets": f"{DOCS}/repos/rules#get-all-repository-rulesets",
    "get-ruleset": f"{DOCS}/repos/rules#get-a-repository-ruleset",
    "create-ruleset": f"{DOCS}/repos/rules#create-a-repository-ruleset",
    "update-ruleset": f"{DOCS}/repos/rules#update-a-repository-ruleset",
    "delete-ruleset": f"{DOCS}/repos/rules#delete-a-repository-ruleset",
    "get-branch-rules": f"{DOCS}/repos/rules#get-rules-for-a-branch",
    "list-reviews": f"{DOCS}/pulls/reviews#list-reviews-for-a-pull-request",
    "create-review": f"{DOCS}/pulls/reviews#create-a-review-for-a-pull-request",
    "dismiss-review": f"{DOCS}/pulls/reviews#dismiss-a-review-for-a-pull-request",
    "dispatch-workflow": f"{DOCS}/actions/workflows#create-a-workflow-dispatch-event",
    "list-workflow-runs": f"{DOCS}/actions/workflow-runs#list-workflow-runs-for-a-workflow",
    "list-repo-runs": f"{DOCS}/actions/workflow-runs#list-workflow-runs-for-a-repository",
    "get-run": f"{DOCS}/actions/workflow-runs#get-a-workflow-run",
}
# Every route has a page; the behaviours inside a route that no page documents are named in the
# module docstring and marked "unsourced" where they are implemented.
UNSOURCED: frozenset[str] = frozenset()

ACTIONS_APP_ID = "15368"  # the GitHub Actions app's ID as it appears on check runs
EXTRA_PERMISSIONS: Mapping[str, str] = {"actions": "write", "administration": "write"}
_LEVELS = {"read": 1, "write": 2, "admin": 3}
_STATUSES = ("queued", "in_progress", "completed")
_CONCLUSIONS = (
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "success",
    "skipped",
    "stale",
    "timed_out",
)
_PASSING = frozenset({"success", "neutral", "skipped"})
_RUN_STATUSES = frozenset(
    {"queued", "in_progress", "completed", "requested", "waiting", "pending", *_CONCLUSIONS}
)
_TARGETS = ("branch", "tag", "push")
_ENFORCEMENTS = ("disabled", "active", "evaluate")
_PLAIN_RULES = (
    "creation", "update", "deletion", "required_linear_history", "required_signatures",
    "non_fast_forward",
)  # fmt: skip
_EVENTS = {"APPROVE": "APPROVED", "REQUEST_CHANGES": "CHANGES_REQUESTED", "COMMENT": "COMMENTED"}
_HEADER = "Repository rule violations found"
_WORKFLOWS = ".github/workflows/"
_MAX_INPUTS = 25


@dataclass(frozen=True)
class Violation:
    """One reason a PR cannot merge, for a guard to explain."""

    kind: str
    subject: str
    message: str


@dataclass
class CheckRun:
    id: int
    name: str
    head_sha: str
    app_id: int
    status: str = "queued"
    conclusion: str | None = None
    external_id: str = ""
    details_url: str | None = None
    output: dict[str, Any] = field(default_factory=dict)
    started_at: float | None = None
    completed_at: float | None = None


@dataclass
class Ruleset:
    id: int
    name: str
    target: str
    enforcement: str
    conditions: dict[str, Any]
    rules: list[dict[str, Any]]
    bypass_actors: list[Any]
    created: float
    updated: float


@dataclass
class Review:
    id: int
    number: int
    user: str
    state: str
    body: str
    commit_id: str
    submitted: float | None
    writer: bool = True


@dataclass
class WorkflowRun:
    id: int
    path: str
    name: str
    number: int
    event: str
    head_branch: str
    head_sha: str
    actor: str
    created: float
    inputs: dict[str, Any]
    status: str = "queued"
    conclusion: str | None = None
    updated: float = 0.0
    check_ids: list[int] = field(default_factory=list)

    @property
    def workflow_id(self) -> int:
        return _workflow_id(self.path)


@dataclass
class _Extra:
    checks: list[CheckRun] = field(default_factory=list)
    rulesets: list[Ruleset] = field(default_factory=list)
    reviews: list[Review] = field(default_factory=list)
    runs: list[WorkflowRun] = field(default_factory=list)


def _workflow_id(path: str) -> int:
    return int(hashlib.sha1(path.encode()).hexdigest()[:7], 16)  # noqa: S324


def _is_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _glob(pattern: str) -> re.Pattern[str]:
    """fnmatch as rulesets write it: ``*`` stays inside a path segment, ``**`` crosses ``/``."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out)


def _plural(n: int) -> str:
    return f"{n} approving review{'' if n == 1 else 's'}"


class FakeGitHubChecks(FakeGitHubPulls):
    """Check runs, rulesets, reviews and workflow dispatch over the fake GitHub's pull requests."""

    ROUTE_NAMES = frozenset(SOURCES) | frozenset(PULLS_SOURCES) | UNSOURCED

    def __init__(self) -> None:
        super().__init__()
        self._extra: dict[str, _Extra] = defaultdict(_Extra)
        self._manual: dict[tuple[str, int], str | None] = {}
        self._ids = 0
        self._run_ids = 5_000_000

    # --- tokens: the two extra permissions --------------------------------------------------

    def create_installation_token(
        self,
        jwt: str,
        installation_id: int,
        repositories: Sequence[str] | None = None,
        permissions: Mapping[str, str] | None = None,
    ) -> Response:
        extra: dict[str, str] = {}
        base = permissions
        if permissions is None:
            extra = dict(EXTRA_PERMISSIONS)
        else:
            extra = {k: v for k, v in permissions.items() if k in EXTRA_PERMISSIONS}
            base = {k: v for k, v in permissions.items() if k not in EXTRA_PERMISSIONS}
            if any(_LEVELS.get(v, 99) > _LEVELS[EXTRA_PERMISSIONS[k]] for k, v in extra.items()):
                base, extra = permissions, {}  # the auth fake refuses what is beyond the grant
        r = super().create_installation_token(jwt, installation_id, repositories, base)
        if r.status == 201 and extra:
            r.body["permissions"].update(extra)  # the same dict the grant holds
        return r

    # --- test controls ----------------------------------------------------------------------

    def add_check_run(
        self,
        sha: str,
        name: str,
        *,
        status: str = "completed",
        conclusion: str | None = "success",
        app_id: int | None = None,
        repo: str = REPO,
    ) -> int:
        """Some CI (another App, by default) reports a check on ``sha``. Returns its ID."""
        run = self._new_check(repo, name, sha, int(APP_ID) if app_id is None else app_id)
        run.status = status
        run.conclusion = conclusion if status == "completed" else None
        if status == "completed":
            run.completed_at = self.now
        return run.id

    def add_review(
        self,
        number: int,
        user: str,
        state: str,
        *,
        writer: bool = True,
        commit_id: str | None = None,
        repo: str = REPO,
    ) -> Review:
        """A person reviews the PR (``state``: APPROVED, CHANGES_REQUESTED or COMMENTED)."""
        r = self.repos[repo]
        pr = self._pull(r, number)
        head = commit_id or r.refs[f"refs/heads/{pr.head}"]
        review = Review(self._next(), number, user, state, "", head, self.now, writer)
        self._extra[repo].reviews.append(review)
        return review

    def set_author(self, number: int, user: str, repo: str = REPO) -> None:
        """The PR was opened by someone else (the fake's own PRs are the App's)."""
        self._pull(self.repos[repo], number).user = user

    def block_merge(self, number: int, message: str | None, repo: str = REPO) -> None:
        """A scripted protection that wins over the rulesets (None lifts it)."""
        self._manual[(repo, number)] = message

    def start_run(self, run_id: int, repo: str = REPO) -> None:
        run = self._find_run(repo, run_id)
        run.status, run.updated = "in_progress", self.now
        for check in self._extra[repo].checks:
            if check.id in run.check_ids:
                check.status, check.started_at = "in_progress", check.started_at or self.now

    def complete_run(self, run_id: int, conclusion: str = "success", repo: str = REPO) -> None:
        assert conclusion in _CONCLUSIONS, conclusion
        run = self._find_run(repo, run_id)
        run.status, run.conclusion, run.updated = "completed", conclusion, self.now
        for check in self._extra[repo].checks:
            if check.id in run.check_ids:
                check.status, check.conclusion, check.completed_at = (
                    "completed",
                    conclusion,
                    self.now,
                )

    def workflow_runs(self, repo: str = REPO) -> list[WorkflowRun]:
        return list(self._extra[repo].runs)

    def protection(self, number: int, repo: str = REPO) -> list[Violation]:
        """Why the rulesets, check runs and reviews stop this PR merging (empty: nothing does)."""
        pr = self._pull(self.repos[repo], number)
        if pr.state != "open":
            return []
        return self._violations(repo, pr)

    # --- ids ----------------------------------------------------------------------------------

    def _next(self) -> int:
        self._ids += 1
        return self._ids

    def _find_run(self, repo: str, run_id: int) -> WorkflowRun:
        return next(x for x in self._extra[repo].runs if x.id == run_id)

    def _full(self, r: Repo) -> str:
        return next(name for name, repo in self.repos.items() if repo is r)

    # --- composition with the pulls fake ------------------------------------------------------

    def _sync_block(self, r: Repo, pr: Pull) -> None:
        full = self._full(r)
        manual = self._manual.get((full, pr.number))
        if manual:
            pr.blocked = manual
        else:
            found = self._violations(full, pr)
            pr.blocked = _HEADER + "\n\n" + "\n\n".join(v.message for v in found) if found else None

    def _pr_json(self, r: Repo, full: str, pr: Pull) -> dict[str, Any]:
        self._sync_block(r, pr)
        return super()._pr_json(r, full, pr)

    def _run(self, r: Repo, req: MergeRequest) -> None:
        self._sync_block(r, self._pull(r, req.number))
        super()._run(r, req)

    def _moved(self, r: Repo, ref: str) -> None:
        super()._moved(r, ref)
        name = ref.removeprefix("refs/heads/")
        full = self._full(r)
        for pr in r.pulls:
            if (
                pr.head == name
                and pr.state == "open"
                and self._rules(full, pr.base, "pull_request")
            ):
                head = r.refs.get(ref, "")
                dismiss = any(
                    rule["parameters"]["dismiss_stale_reviews_on_push"]
                    for _, rule in self._rules(full, pr.base, "pull_request")
                )
                for review in self._extra[full].reviews:
                    stale = review.state == "APPROVED" and review.commit_id != head
                    if dismiss and review.number == pr.number and stale:
                        review.state = "DISMISSED"

    # --- rules --------------------------------------------------------------------------------

    def _matches(self, rs: Ruleset, ref: str) -> bool:
        kind = "branch" if ref.startswith("refs/heads/") else "tag"
        if rs.enforcement != "active" or rs.target != kind:
            return False
        names = rs.conditions.get("ref_name")
        if not isinstance(names, dict):
            return False  # unsourced: no conditions, no targets

        def hit(pattern: str) -> bool:
            if pattern == "~ALL":
                return True
            if pattern == "~DEFAULT_BRANCH":
                return ref == "refs/heads/main"
            full = pattern if pattern.startswith("refs/") else f"refs/{kind}s/{pattern}"
            return _glob(full).fullmatch(ref) is not None

        return any(hit(p) for p in names.get("include", [])) and not any(
            hit(p) for p in names.get("exclude", [])
        )

    def _ref_rules(self, full: str, ref: str) -> list[tuple[Ruleset, dict[str, Any]]]:
        return [
            (rs, rule)
            for rs in self._extra[full].rulesets
            if self._matches(rs, ref)
            for rule in rs.rules
        ]

    def _rules(self, full: str, branch: str, kind: str) -> list[tuple[Ruleset, dict[str, Any]]]:
        return [x for x in self._ref_rules(full, f"refs/heads/{branch}") if x[1]["type"] == kind]

    def _latest_checks(self, full: str, sha: str) -> dict[tuple[int, str], CheckRun]:
        best: dict[tuple[int, str], CheckRun] = {}
        for run in self._extra[full].checks:  # ascending IDs: the last one wins
            if run.head_sha == sha:
                best[(run.app_id, run.name)] = run
        return best

    def _violations(self, full: str, pr: Pull) -> list[Violation]:
        r = self.repos[full]
        head, base = r.refs.get(f"refs/heads/{pr.head}"), r.refs.get(f"refs/heads/{pr.base}")
        found: list[Violation] = []
        seen: set[tuple[str, str]] = set()

        def add(kind: str, subject: str, message: str) -> None:
            if (kind, subject) not in seen:
                seen.add((kind, subject))
                found.append(Violation(kind, subject, message))

        if head is None:
            return found
        latest = self._latest_checks(full, head)
        for _, rule in self._rules(full, pr.base, "required_status_checks"):
            params = rule["parameters"]
            for need in params["required_status_checks"]:
                context, pin = need["context"], need.get("integration_id")
                runs = [v for (app, name), v in latest.items() if name == context
                        and (pin is None or app == pin)]  # fmt: skip
                passing = any(x.status == "completed" and x.conclusion in _PASSING for x in runs)
                waiting = not runs or any(x.status != "completed" for x in runs)
                if passing:
                    continue
                if waiting:
                    text = f'Required status check "{context}" is expected.'
                    add("check_expected", context, text)
                else:
                    add("check_failing", context, f'Required status check "{context}" is failing.')
            behind = base is not None and base not in self._ancestors(r, head)
            if params["strict_required_status_checks_policy"] and behind:
                text = "Required status checks require the branch to be up to date before merging."
                add("not_up_to_date", "", text)
        for _, rule in self._rules(full, pr.base, "pull_request"):
            need_n = rule["parameters"]["required_approving_review_count"]
            standing = self._standing(full, pr)
            approvals = sum(1 for s in standing.values() if s == "APPROVED")
            if approvals < need_n:
                add(
                    "approvals_missing", "",
                    f"At least {_plural(need_n)} "
                    f"{'is' if need_n == 1 else 'are'} required by reviewers with write access.",
                )  # fmt: skip
            if "CHANGES_REQUESTED" in standing.values():
                add("changes_requested", "", "Changes have been requested by a reviewer.")
        return found

    def _standing(self, full: str, pr: Pull) -> dict[str, str]:
        """Each reviewer with write access, and their latest APPROVED, CHANGES_REQUESTED or
        DISMISSED review (a comment changes nothing)."""
        standing: dict[str, str] = {}
        for review in self._extra[full].reviews:
            if review.number == pr.number and review.writer and review.state in (
                "APPROVED", "CHANGES_REQUESTED", "DISMISSED",
            ):  # fmt: skip
                standing[review.user] = review.state
        return standing

    # --- ref routes under rules ---------------------------------------------------------------

    def _ref_refusal(self, c: _Call, ref: str, kinds: Sequence[str]) -> Response | None:
        for _, rule in self._ref_rules(c.full, ref):
            if rule["type"] in kinds:
                words = {
                    "creation": "Cannot create ref due to creations being restricted.",
                    "update": "Cannot update this protected ref.",
                    "deletion": "Cannot delete this protected ref.",
                    "non_fast_forward": "Cannot force-push to this ref.",
                }
                return _err(422, f"{_HEADER}\n\n{words[rule['type']]}", c.quota)
        return None

    def _h_delete_ref(self, c: _Call) -> Response:
        ref = "refs/" + c.match[1]
        if ref in c.repo.refs and ref != "refs/heads/main":
            refused = self._ref_refusal(c, ref, ("deletion",))
            if refused is not None:
                return refused
        return super()._h_delete_ref(c)

    def _h_create_ref(self, c: _Call) -> Response:
        ref = c.body.get("ref")
        if isinstance(ref, str) and ref not in c.repo.refs:
            refused = self._ref_refusal(c, ref, ("creation",))
            if refused is not None:
                return refused
        return super()._h_create_ref(c)

    def _h_update_ref(self, c: _Call) -> Response:
        ref, sha = "refs/" + c.match[1], c.body.get("sha")
        if ref in c.repo.refs:
            kinds = ["update"]
            rewinds = (
                isinstance(sha, str)
                and sha in c.repo.commits
                and c.repo.refs[ref] not in self._ancestors(c.repo, sha)
            )
            if rewinds:
                kinds.append("non_fast_forward")
            refused = self._ref_refusal(c, ref, kinds)
            if refused is not None:
                return refused
        return super()._h_update_ref(c)

    def _h_merge_branch(self, c: _Call) -> Response:
        base = c.body.get("base")
        if isinstance(base, str) and f"refs/heads/{base}" in c.repo.refs:
            kinds = ("update", "pull_request", "required_status_checks")
            for _, rule in self._ref_rules(c.full, f"refs/heads/{base}"):
                if rule["type"] in kinds:  # unsourced: a direct merge is a push to the base
                    return _err(
                        409, f"{_HEADER}\n\nChanges must be made through a pull request.", c.quota
                    )
        return super()._h_merge_branch(c)

    # --- routes -------------------------------------------------------------------------------

    _CHK = (("checks", "read"),)
    _CHK_W = (("checks", "write"),)
    _META = (("metadata", "read"),)
    _ADMIN_W = (("administration", "write"),)
    _ACT = (("actions", "read"),)
    _ACT_W = (("actions", "write"),)
    _ROUTES: Sequence[tuple[str, str, str, str, tuple[tuple[str, str], ...]]] = (
        *FakeGitHubPulls._ROUTES,
        ("POST", r"/check-runs", "create-check-run", "create-check-run", _CHK_W),
        ("PATCH", r"/check-runs/(\d+)", "update-check-run", "update-check-run", _CHK_W),
        ("GET", r"/check-runs/(\d+)", "get-check-run", "get-check-run", _CHK),
        (
            "GET",
            r"/commits/(.+)/check-runs",
            "list-check-runs-for-ref",
            "list-check-runs-for-ref",
            _CHK,
        ),  # fmt: skip
        ("GET", r"/rulesets", "list-rulesets", "list-rulesets", _META),
        ("GET", r"/rulesets/(\d+)", "get-ruleset", "get-ruleset", _META),
        ("POST", r"/rulesets", "create-ruleset", "create-ruleset", _ADMIN_W),
        ("PUT", r"/rulesets/(\d+)", "update-ruleset", "update-ruleset", _ADMIN_W),
        ("DELETE", r"/rulesets/(\d+)", "delete-ruleset", "delete-ruleset", _ADMIN_W),
        ("GET", r"/rules/branches/(.+)", "get-branch-rules", "get-branch-rules", _META),
        (
            "GET",
            r"/pulls/(\d+)/reviews",
            "list-reviews",
            "list-reviews",
            (("pull_requests", "read"),),
        ),  # fmt: skip
        (
            "POST",
            r"/pulls/(\d+)/reviews",
            "create-review",
            "create-review",
            (("pull_requests", "write"),),
        ),  # fmt: skip
        (
            "PUT",
            r"/pulls/(\d+)/reviews/(\d+)/dismissals",
            "dismiss-review",
            "dismiss-review",
            (("pull_requests", "write"),),
        ),  # fmt: skip
        (
            "POST",
            r"/actions/workflows/([^/]+)/dispatches",
            "dispatch",
            "dispatch-workflow",
            _ACT_W,
        ),  # fmt: skip
        (
            "GET",
            r"/actions/workflows/([^/]+)/runs",
            "list-workflow-runs",
            "list-workflow-runs",
            _ACT,
        ),  # fmt: skip
        ("GET", r"/actions/runs", "list-repo-runs", "list-repo-runs", _ACT),
        ("GET", r"/actions/runs/(\d+)", "get-run", "get-run", _ACT),
    )

    # --- check runs ---------------------------------------------------------------------------

    def _new_check(self, full: str, name: str, sha: str, app_id: int) -> CheckRun:
        run = CheckRun(self._next(), name, sha, app_id, started_at=self.now)
        self._extra[full].checks.append(run)
        return run

    def _check_json(self, c_full: str, run: CheckRun) -> dict[str, Any]:
        r = self.repos[c_full]
        prs = [
            {
                "number": p.number,
                "url": f"{HOST}/repos/{c_full}/pulls/{p.number}",
                "head": {"ref": p.head, "sha": r.refs.get(f"refs/heads/{p.head}", "")},
                "base": {"ref": p.base, "sha": r.refs.get(f"refs/heads/{p.base}", "")},
            }
            for p in r.pulls
            if p.state == "open" and r.refs.get(f"refs/heads/{p.head}") == run.head_sha
        ]
        slug = "github-actions" if run.app_id == int(ACTIONS_APP_ID) else f"app-{run.app_id}"
        return {
            "id": run.id,
            "name": run.name,
            "head_sha": run.head_sha,
            "external_id": run.external_id,
            "status": run.status,
            "conclusion": run.conclusion,
            "started_at": None if run.started_at is None else _iso(run.started_at),
            "completed_at": None if run.completed_at is None else _iso(run.completed_at),
            "output": {
                "title": run.output.get("title"),
                "summary": run.output.get("summary"),
                "text": run.output.get("text"),
                "annotations_count": 0,
            },
            "details_url": run.details_url,
            "url": f"{HOST}/repos/{c_full}/check-runs/{run.id}",
            "html_url": f"https://github.test/{c_full}/runs/{run.id}",
            "app": {"id": run.app_id, "slug": slug, "name": slug},
            "check_suite": {"id": run.id},
            "pull_requests": prs,
        }

    def _check_fields(self, c: _Call, *, creating: bool) -> Response | None:
        b, q = c.body, c.quota
        names = ("name", "head_sha") if creating else ()
        for name in names:
            if name not in b:
                return _invalid(name, "nil is not a string", q)
        for name in ("name", "head_sha", "details_url", "external_id", "status", "conclusion"):
            if name in b and not isinstance(b[name], str):
                return _invalid(name, f"{b[name]!r} is not a string", q)
        if "status" in b and b["status"] not in _STATUSES:
            return _invalid("status", f"{b['status']!r} is not one of {list(_STATUSES)}", q)
        if "conclusion" in b and b["conclusion"] not in _CONCLUSIONS:
            return _invalid(
                "conclusion", f"{b['conclusion']!r} is not one of {list(_CONCLUSIONS)}", q
            )
        for name in ("started_at", "completed_at"):
            if name in b and not _is_time(b[name]):
                return _invalid(name, f"{b[name]!r} is not a date-time", q)
        if "output" in b:
            out = b["output"]
            ok = isinstance(out, dict) and all(
                isinstance(out.get(k), str) for k in ("title", "summary")
            )
            if not ok:
                return _invalid("output", f"{out!r} needs a string title and summary", q)
        return None

    def _completion(self, c: _Call, run: CheckRun | None) -> Response | None:
        """A completed run needs a conclusion (documented): given now or already held."""
        b = c.body
        held = run.conclusion if run else None
        status = b.get("status", run.status if run else "queued")
        if (status == "completed" or "completed_at" in b) and not (b.get("conclusion") or held):
            return _validation(c.quota, "CheckRun", "conclusion", "missing_field")
        return None

    def _apply_check(self, run: CheckRun, b: Mapping[str, Any]) -> None:
        for name in ("name", "details_url", "external_id"):
            if name in b:
                setattr(run, name, b[name])
        if "output" in b:
            run.output = dict(b["output"])
        if "status" in b:
            run.status = b["status"]
        if "conclusion" in b:
            run.conclusion, run.status = b["conclusion"], "completed"  # documented
        if "started_at" in b:
            run.started_at = datetime.fromisoformat(
                b["started_at"].replace("Z", "+00:00")
            ).timestamp()
        if run.status == "completed":
            run.completed_at = (
                datetime.fromisoformat(b["completed_at"].replace("Z", "+00:00")).timestamp()
                if "completed_at" in b
                else run.completed_at or self.now
            )

    def _h_create_check_run(self, c: _Call) -> Response:
        refused = self._check_fields(c, creating=True) or self._completion(c, None)
        if refused is not None:
            return refused
        sha = c.body["head_sha"]
        if sha not in c.repo.commits:  # unsourced wording
            return _err(422, f"No commit found for SHA: {sha}", c.quota)
        run = self._new_check(c.full, c.body["name"], sha, int(APP_ID))
        self._apply_check(run, c.body)
        return _ok(201, self._check_json(c.full, run), c.quota)

    def _find_check(self, c: _Call) -> CheckRun | Response:
        found = [x for x in self._extra[c.full].checks if x.id == int(c.match[1])]
        return found[0] if found else _err(404, "Not Found", c.quota)

    def _h_get_check_run(self, c: _Call) -> Response:
        run = self._find_check(c)
        if isinstance(run, Response):
            return run
        return _ok(200, self._check_json(c.full, run), c.quota)

    def _h_update_check_run(self, c: _Call) -> Response:
        run = self._find_check(c)
        if isinstance(run, Response):
            return run
        refused = self._check_fields(c, creating=False) or self._completion(c, run)
        if refused is not None:
            return refused
        if run.app_id != int(APP_ID):  # unsourced status: an App updates its own runs only
            return _err(403, "Resource not accessible by integration", c.quota)
        self._apply_check(run, c.body)
        return _ok(200, self._check_json(c.full, run), c.quota)

    def _resolve(self, r: Repo, ref: str) -> str | None:
        if ref in r.commits:
            return ref
        for candidate in (
            f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/{ref}", ref,
        ):  # fmt: skip
            if candidate in r.refs:
                return r.refs[candidate]
        return None

    def _h_list_check_runs_for_ref(self, c: _Call) -> Response:
        q = c.query
        sha = self._resolve(c.repo, c.match[1])
        if sha is None:  # unsourced wording
            return _err(422, f"No commit found for SHA: {c.match[1]}", c.quota)
        if q.get("filter", "latest") not in ("latest", "all"):
            return _invalid("filter", f"{q['filter']!r} is not one of ['latest', 'all']", c.quota)
        if "status" in q and q["status"] not in _STATUSES:
            return _invalid("status", f"{q['status']!r} is not one of {list(_STATUSES)}", c.quota)
        if "app_id" in q and not q["app_id"].isdigit():
            return _invalid("app_id", f"{q['app_id']!r} is not an integer", c.quota)
        rows = [x for x in self._extra[c.full].checks if x.head_sha == sha]
        if q.get("filter", "latest") == "latest":
            newest = {(x.app_id, x.name): x.id for x in rows}
            rows = [x for x in rows if newest[(x.app_id, x.name)] == x.id]
        rows = [
            x
            for x in rows
            if q.get("check_name", x.name) == x.name
            and q.get("status", x.status) == x.status
            and q.get("app_id", str(x.app_id)) == str(x.app_id)
        ]
        route = f"/repos/{c.full}/commits/{c.match[1]}/check-runs"
        chunk, headers = self._paginate(rows, c, route)
        body = {
            "total_count": len(rows),
            "check_runs": [self._check_json(c.full, x) for x in chunk],
        }
        return _ok(200, body, c.quota, **headers)

    # --- rulesets -----------------------------------------------------------------------------

    def _ruleset_json(self, c_full: str, rs: Ruleset, *, full: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": rs.id,
            "name": rs.name,
            "target": rs.target,
            "source_type": "Repository",
            "source": c_full,
            "enforcement": rs.enforcement,
            "created_at": _iso(rs.created),
            "updated_at": _iso(rs.updated),
        }
        if full:
            out |= {
                "conditions": rs.conditions,
                "rules": rs.rules,
                "bypass_actors": rs.bypass_actors,
                "current_user_can_bypass": "never",
            }
        return out

    @staticmethod
    def _bool_params(params: Any, names: Sequence[str]) -> str | None:
        for name in names:
            if not isinstance(params.get(name), bool):
                return name
        return None

    def _check_rules(self, rules: Any, q: Mapping[str, str]) -> Response | None:
        if not isinstance(rules, list):
            return _invalid("rules", f"{rules!r} is not an array", q)
        for rule in rules:
            kind = rule.get("type") if isinstance(rule, dict) else None
            params = rule.get("parameters", {}) if isinstance(rule, dict) else None
            if kind in _PLAIN_RULES:
                continue
            if kind not in ("required_status_checks", "pull_request"):
                return _validation(q, "Ruleset", "rules", "invalid", f"unknown rule type {kind!r}")
            if not isinstance(params, dict):
                return _invalid("rules/parameters", f"{params!r} is not an object", q)
            if kind == "required_status_checks":
                needs = params.get("required_status_checks")
                if not isinstance(needs, list) or not all(
                    isinstance(n, dict)
                    and isinstance(n.get("context"), str)
                    and (n.get("integration_id") is None or isinstance(n["integration_id"], int))
                    for n in needs
                ):
                    return _invalid(
                        "required_status_checks", f"{needs!r} is not a list of checks", q
                    )
                if self._bool_params(params, ("strict_required_status_checks_policy",)):
                    return _invalid("strict_required_status_checks_policy", "is required", q)
            else:
                count = params.get("required_approving_review_count")
                if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 10:
                    return _invalid("required_approving_review_count", f"{count!r} is not 0-10", q)
                missing = self._bool_params(
                    params,
                    (
                        "dismiss_stale_reviews_on_push", "require_code_owner_review",
                        "require_last_push_approval", "required_review_thread_resolution",
                    ),
                )  # fmt: skip
                if missing:
                    return _invalid(missing, "is required", q)
        return None

    def _check_ruleset(self, c: _Call, *, creating: bool, own: int | None) -> Response | None:
        b, q = c.body, c.quota
        for name in ("name", "enforcement") if creating else ():
            if b.get(name) is None:
                return _invalid(name, "nil is not a string", q)
        if "name" in b and (not isinstance(b["name"], str) or not b["name"]):
            return _invalid("name", f"{b['name']!r} is not a string", q)
        if "target" in b and b["target"] not in _TARGETS:
            return _invalid("target", f"{b['target']!r} is not one of {list(_TARGETS)}", q)
        if "enforcement" in b and b["enforcement"] not in _ENFORCEMENTS:
            return _invalid(
                "enforcement", f"{b['enforcement']!r} is not one of {list(_ENFORCEMENTS)}", q
            )
        if "bypass_actors" in b and not isinstance(b["bypass_actors"], list):
            return _invalid("bypass_actors", f"{b['bypass_actors']!r} is not an array", q)
        if "conditions" in b:
            cond = b["conditions"]
            names = cond.get("ref_name") if isinstance(cond, dict) else None
            if not isinstance(cond, dict) or (
                names is not None
                and not (
                    isinstance(names, dict)
                    and all(
                        isinstance(names.get(k, []), list)
                        and all(isinstance(p, str) for p in names.get(k, []))
                        for k in ("include", "exclude")
                    )
                )
            ):
                return _invalid("conditions", f"{cond!r} is not a ref name condition", q)
        if "rules" in b:
            refused = self._check_rules(b["rules"], q)
            if refused is not None:
                return refused
        taken = any(x.name == b.get("name") and x.id != own for x in self._extra[c.full].rulesets)
        if taken:  # unsourced wording
            return _validation(q, "Ruleset", "name", "custom", "Name must be unique")
        return None

    def _find_ruleset(self, c: _Call) -> Ruleset | Response:
        found = [x for x in self._extra[c.full].rulesets if x.id == int(c.match[1])]
        return found[0] if found else _err(404, "Not Found", c.quota)

    def _h_list_rulesets(self, c: _Call) -> Response:
        rows = list(self._extra[c.full].rulesets)
        if "targets" in c.query:
            wanted = c.query["targets"].split(",")
            rows = [x for x in rows if x.target in wanted]
        chunk, headers = self._paginate(rows, c, f"/repos/{c.full}/rulesets")
        return _ok(
            200, [self._ruleset_json(c.full, x, full=False) for x in chunk], c.quota, **headers
        )

    def _h_get_ruleset(self, c: _Call) -> Response:
        rs = self._find_ruleset(c)
        if isinstance(rs, Response):
            return rs
        return _ok(200, self._ruleset_json(c.full, rs), c.quota)

    def _h_create_ruleset(self, c: _Call) -> Response:
        refused = self._check_ruleset(c, creating=True, own=None)
        if refused is not None:
            return refused
        b = c.body
        rs = Ruleset(
            self._next(), b["name"], b.get("target", "branch"), b["enforcement"],
            dict(b.get("conditions") or {}), list(b.get("rules") or []),
            list(b.get("bypass_actors") or []), self.now, self.now,
        )  # fmt: skip
        self._extra[c.full].rulesets.append(rs)
        return _ok(201, self._ruleset_json(c.full, rs), c.quota)

    def _h_update_ruleset(self, c: _Call) -> Response:
        rs = self._find_ruleset(c)
        if isinstance(rs, Response):
            return rs
        refused = self._check_ruleset(c, creating=False, own=rs.id)
        if refused is not None:
            return refused
        b = c.body
        for name in ("name", "target", "enforcement"):
            if name in b:
                setattr(rs, name, b[name])
        if "conditions" in b:
            rs.conditions = dict(b["conditions"])
        if "rules" in b:
            rs.rules = list(b["rules"])
        if "bypass_actors" in b:
            rs.bypass_actors = list(b["bypass_actors"])
        rs.updated = self.now
        return _ok(200, self._ruleset_json(c.full, rs), c.quota)

    def _h_delete_ruleset(self, c: _Call) -> Response:
        rs = self._find_ruleset(c)
        if isinstance(rs, Response):
            return rs
        self._extra[c.full].rulesets.remove(rs)
        return _ok(204, None, c.quota)

    def _h_get_branch_rules(self, c: _Call) -> Response:
        out = []
        for rs, rule in self._ref_rules(c.full, f"refs/heads/{c.match[1]}"):
            row: dict[str, Any] = {
                "type": rule["type"],
                "ruleset_source_type": "Repository",
                "ruleset_source": c.full,
                "ruleset_id": rs.id,
            }
            if rule.get("parameters"):
                row["parameters"] = rule["parameters"]
            out.append(row)
        return _ok(200, out, c.quota)

    # --- reviews ------------------------------------------------------------------------------

    @staticmethod
    def _review_json(full: str, x: Review) -> dict[str, Any]:
        return {
            "id": x.id,
            "user": {"login": x.user},
            "body": x.body,
            "state": x.state,
            "commit_id": x.commit_id,
            "submitted_at": None if x.submitted is None else _iso(x.submitted),
            "html_url": f"https://github.test/{full}/pull/{x.number}#pullrequestreview-{x.id}",
            "pull_request_url": f"{HOST}/repos/{full}/pulls/{x.number}",
            "author_association": "MEMBER" if x.writer else "NONE",
        }

    def _h_list_reviews(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        rows = [
            x
            for x in self._extra[c.full].reviews
            if x.number == pr.number and (x.state != "PENDING" or x.user == PRINCIPAL)
        ]
        chunk, headers = self._paginate(rows, c, f"/repos/{c.full}/pulls/{pr.number}/reviews")
        return _ok(200, [self._review_json(c.full, x) for x in chunk], c.quota, **headers)

    def _h_create_review(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        b, q = c.body, c.quota
        for name in ("body", "commit_id"):
            if name in b and not isinstance(b[name], str):
                return _invalid(name, f"{b[name]!r} is not a string", q)
        event = b.get("event")
        if event is not None and event not in _EVENTS:
            return _invalid("event", f"{event!r} is not one of {list(_EVENTS)}", q)
        commit = b.get("commit_id") or c.repo.refs.get(f"refs/heads/{pr.head}", "")
        if commit not in c.repo.commits:
            return _validation(q, "PullRequestReview", "commit_id", "invalid")
        if event in ("REQUEST_CHANGES", "COMMENT") and not b.get("body"):
            return _validation(q, "PullRequestReview", "body", "missing_field")
        if event in ("APPROVE", "REQUEST_CHANGES") and pr.user == PRINCIPAL:
            what = "approve" if event == "APPROVE" else "request changes on"  # unsourced wording
            return _validation(
                q, "PullRequestReview", "", "custom", f"Can not {what} your own pull request"
            )
        review = Review(
            self._next(), pr.number, PRINCIPAL, _EVENTS.get(event or "", "PENDING"),
            b.get("body", ""), commit, None if event is None else self.now,
        )  # fmt: skip
        self._extra[c.full].reviews.append(review)
        return _ok(200, self._review_json(c.full, review), q)

    def _h_dismiss_review(self, c: _Call) -> Response:
        pr = self._find_pull(c)
        if isinstance(pr, Response):
            return pr
        found = [
            x for x in self._extra[c.full].reviews
            if x.id == int(c.match[2]) and x.number == pr.number
        ]  # fmt: skip
        if not found:
            return _err(404, "Not Found", c.quota)
        message = c.body.get("message")
        if not isinstance(message, str):
            return _invalid("message", f"{message!r} is not a string", c.quota)
        review = found[0]
        if review.state not in ("APPROVED", "CHANGES_REQUESTED"):  # unsourced wording
            text = f"Can not dismiss a {review.state.lower()} review"
            return _validation(c.quota, "PullRequestReview", "", "custom", text)
        review.state = "DISMISSED"
        return _ok(200, self._review_json(c.full, review), c.quota)

    # --- workflows and runs -------------------------------------------------------------------

    def _workflow_files(self, r: Repo, ref_sha: str) -> dict[str, str]:
        tree = r.trees[r.commits[ref_sha].tree]
        return {
            path: r.blobs[blob]
            for path, blob in tree.items()
            if path.startswith(_WORKFLOWS) and path.endswith((".yml", ".yaml"))
        }

    @staticmethod
    def _workflow_doc(text: str) -> dict[str, Any]:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return {}
        return doc if isinstance(doc, dict) else {}

    @staticmethod
    def _dispatch_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
        """The ``workflow_dispatch`` section ({} when bare), or None if it is not a trigger.
        YAML 1.1 reads the key ``on`` as True."""
        on = doc["on"] if "on" in doc else doc.get(True)  # type: ignore[call-overload]
        if isinstance(on, str):
            return {} if on == "workflow_dispatch" else None
        if isinstance(on, list):
            return {} if "workflow_dispatch" in on else None
        if isinstance(on, dict) and "workflow_dispatch" in on:
            section = on["workflow_dispatch"]
            return section if isinstance(section, dict) else {}
        return None

    def _locate(self, c: _Call, key: str) -> str | None:
        """The workflow's path, by numeric ID or file name, from the DEFAULT branch."""
        main = c.repo.refs["refs/heads/main"]
        for path in self._workflow_files(c.repo, main):
            if key.isdigit() and int(key) == _workflow_id(path):
                return path
            if key in (path, path.removeprefix(_WORKFLOWS)):
                return path
        return None

    def _ref_target(self, r: Repo, ref: str) -> tuple[str, str] | None:
        """(branch or tag name, commit SHA) for ``ref`` as dispatch accepts it."""
        for prefix in ("refs/heads/", "refs/tags/"):
            if ref.startswith(prefix):
                sha = r.refs.get(ref)
                return (ref.removeprefix(prefix), sha) if sha else None
        for prefix in ("refs/heads/", "refs/tags/"):
            if prefix + ref in r.refs:
                return ref, r.refs[prefix + ref]
        return None

    def _inputs(self, spec: Mapping[str, Any], given: Any, q: Mapping[str, str]) -> Any:
        """The inputs a run starts with, or a refusing Response."""
        declared: dict[str, Any] = spec["inputs"] if isinstance(spec.get("inputs"), dict) else {}
        if given is not None and not isinstance(given, dict):
            return _invalid("inputs", f"{given!r} is not an object", q)
        given = given or {}
        if len(given) > _MAX_INPUTS:
            return _invalid("inputs", f"has more than {_MAX_INPUTS} properties", q)
        for key, value in given.items():
            if not isinstance(value, str | int | float | bool):
                return _invalid(f"inputs/{key}", f"{value!r} is not a string", q)
        unknown = [k for k in given if k not in declared]
        if unknown:
            return _err(422, f"Unexpected inputs provided: {unknown!r}".replace("'", '"'), q)
        out: dict[str, Any] = {}
        for key, rule in declared.items():
            rule = rule if isinstance(rule, dict) else {}
            if key in given:
                value = given[key]
                options = rule.get("options")
                if isinstance(options, list) and str(value) not in [str(o) for o in options]:
                    text = f"Provided value '{value}' for input '{key}' not in the list of allowed"
                    return _err(422, f"{text} values", q)
                out[key] = value
            elif "default" in rule:
                out[key] = rule["default"]
            elif rule.get("required"):
                return _err(422, f"Required input '{key}' not provided", q)
        return out

    def _h_dispatch_workflow(self, c: _Call) -> Response:
        path = self._locate(c, c.match[1])
        if path is None:
            return _err(404, "Not Found", c.quota)
        b, q = c.body, c.quota
        if not isinstance(b.get("ref"), str):
            return _invalid("ref", f"{b.get('ref')!r} is not a string", q)
        if "return_run_details" in b and not isinstance(b["return_run_details"], bool):
            return _invalid(
                "return_run_details", f"{b['return_run_details']!r} is not a boolean", q
            )
        target = self._ref_target(c.repo, b["ref"])
        if target is None:  # unsourced wording
            return _err(422, f"No ref found for: {b['ref']}", q)
        name, sha = target
        text = self._workflow_files(c.repo, sha).get(path)
        if text is None:
            return _err(404, "Not Found", q)
        doc = self._workflow_doc(text)
        spec = self._dispatch_spec(doc)
        if spec is None:
            return _err(422, "Workflow does not have 'workflow_dispatch' trigger", q)
        inputs = self._inputs(spec, b.get("inputs"), q)
        if isinstance(inputs, Response):
            return inputs
        extra = self._extra[c.full]
        self._run_ids += 1
        number = 1 + sum(1 for x in extra.runs if x.path == path)
        run = WorkflowRun(
            self._run_ids, path, str(doc.get("name") or path.removeprefix(_WORKFLOWS)), number,
            "workflow_dispatch", name, sha, PRINCIPAL, self.now, inputs, updated=self.now,
        )  # fmt: skip
        jobs: dict[str, Any] = doc["jobs"] if isinstance(doc.get("jobs"), dict) else {}
        for key, job in jobs.items():
            label = job.get("name") if isinstance(job, dict) and job.get("name") else key
            run.check_ids.append(self._new_check(c.full, str(label), sha, int(ACTIONS_APP_ID)).id)
        extra.runs.append(run)
        if b.get("return_run_details"):
            body = {
                "workflow_run_id": run.id,
                "run_url": f"{HOST}/repos/{c.full}/actions/runs/{run.id}",
                "html_url": f"https://github.test/{c.full}/actions/runs/{run.id}",
            }
            return _ok(200, body, q)
        return _ok(204, None, q)

    def _run_json(self, full: str, x: WorkflowRun) -> dict[str, Any]:
        return {
            "id": x.id,
            "name": x.name,
            "display_title": x.name,
            "head_branch": x.head_branch,
            "head_sha": x.head_sha,
            "path": x.path,
            "run_number": x.number,
            "run_attempt": 1,
            "event": x.event,
            "status": x.status,
            "conclusion": x.conclusion,
            "workflow_id": x.workflow_id,
            "actor": {"login": x.actor},
            "triggering_actor": {"login": x.actor},
            "url": f"{HOST}/repos/{full}/actions/runs/{x.id}",
            "html_url": f"https://github.test/{full}/actions/runs/{x.id}",
            "created_at": _iso(x.created),
            "updated_at": _iso(x.updated),
            "run_started_at": _iso(x.created),
        }

    @staticmethod
    def _created(value: str, stamp: str) -> bool:
        """The ``created`` filter: ``>=T``, ``>T``, ``<=T``, ``<T``, ``A..B`` or ``T``; a date
        compares by day."""

        def key(text: str) -> str:
            return stamp[: len(text)]

        if ".." in value:
            low, _, high = value.partition("..")
            return low <= key(low) and key(high) <= high
        for op in (">=", "<=", ">", "<"):
            if value.startswith(op):
                bound = value[len(op) :]
                k = key(bound)
                return {">=": k >= bound, "<=": k <= bound, ">": k > bound, "<": k < bound}[op]
        return key(value) == value

    def _list_runs(self, c: _Call, rows: list[WorkflowRun], route: str) -> Response:
        q = c.query
        if "status" in q and q["status"] not in _RUN_STATUSES:
            return _invalid("status", f"{q['status']!r} is not a status or conclusion", c.quota)
        rows = [
            x
            for x in rows
            if q.get("actor", x.actor) == x.actor
            and q.get("branch", x.head_branch) == x.head_branch
            and q.get("event", x.event) == x.event
            and q.get("head_sha", x.head_sha) == x.head_sha
            and q.get("status") in (None, x.status, x.conclusion)
            and ("created" not in q or self._created(q["created"], _iso(x.created)))
        ]
        rows.sort(key=lambda x: x.id, reverse=True)
        chunk, headers = self._paginate(rows, c, route)
        body = {
            "total_count": len(rows),
            "workflow_runs": [self._run_json(c.full, x) for x in chunk],
        }
        return _ok(200, body, c.quota, **headers)

    def _h_list_workflow_runs(self, c: _Call) -> Response:
        path = self._locate(c, c.match[1])
        if path is None:
            return _err(404, "Not Found", c.quota)
        rows = [x for x in self._extra[c.full].runs if x.path == path]
        return self._list_runs(c, rows, f"/repos/{c.full}/actions/workflows/{c.match[1]}/runs")

    def _h_list_repo_runs(self, c: _Call) -> Response:
        return self._list_runs(c, list(self._extra[c.full].runs), f"/repos/{c.full}/actions/runs")

    def _h_get_run(self, c: _Call) -> Response:
        found = [x for x in self._extra[c.full].runs if x.id == int(c.match[1])]
        if not found:
            return _err(404, "Not Found", c.quota)
        return _ok(200, self._run_json(c.full, found[0]), c.quota)


__all__ = ["OWNER", "REPO", "SOURCES", "UNSOURCED", "FakeGitHubChecks", "Violation"]
