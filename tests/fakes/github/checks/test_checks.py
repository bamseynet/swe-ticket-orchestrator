"""D4-20: check runs, required checks, rulesets, reviews and workflow dispatch, route by route.

Each test names the docs.github.com page it follows, or says "unsourced" where the fake's own
server.py lists the behaviour as a departure to prove live (D4-23). The three acceptance criteria
are the first three sections: a pending required check blocks a merge, ``neutral`` passes, and a
dispatch's run ID exists only in its response.
"""

from __future__ import annotations

from typing import Any

import pytest

from fakes.github.auth import APP_ID
from fakes.github.checks import (
    ACTIONS_APP_ID,
    REPO,
    SOURCES,
    UNSOURCED,
    FakeGitHubChecks,
    Response,
)
from fakes.github.pulls import SOURCES as PULLS_SOURCES

R = f"/repos/{REPO}"
WORKFLOW = """\
name: CI
on:
  workflow_dispatch:
    inputs:
      target:
        required: true
        type: choice
        options: [staging, prod]
      note:
        default: none
jobs:
  build:
    runs-on: ubuntu-latest
  lint:
    name: Lint code
    runs-on: ubuntu-latest
"""
PUSH_ONLY = "name: Push\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n"


@pytest.fixture
def gh() -> FakeGitHubChecks:
    return FakeGitHubChecks()


@pytest.fixture
def tok(gh: FakeGitHubChecks) -> str:
    return gh.mint()


def call(gh: FakeGitHubChecks, tok: str, method: str, path: str, **kw: Any) -> Response:
    return gh.request(method, R + path, tok, **kw)


def open_pr(gh: FakeGitHubChecks, tok: str, branch: str = "feat", **kw: Any) -> dict[str, Any]:
    if gh.sha(REPO, branch) is None:
        gh.push(REPO, branch, {f"{branch}.txt": "x"})
    r = call(gh, tok, "POST", "/pulls", json={"title": "t", "head": branch, "base": "main", **kw})
    assert r.status == 201, r.body
    return r.body  # type: ignore[no-any-return]


def head_of(pr: dict[str, Any]) -> str:
    return str(pr["head"]["sha"])


def check(gh: FakeGitHubChecks, tok: str, sha: str, name: str = "ci", **kw: Any) -> dict[str, Any]:
    r = call(gh, tok, "POST", "/check-runs", json={"name": name, "head_sha": sha, **kw})
    assert r.status == 201, r.body
    return r.body  # type: ignore[no-any-return]


def ruleset(
    gh: FakeGitHubChecks, tok: str, rules: list[dict[str, Any]], **kw: Any
) -> dict[str, Any]:
    body = {
        "name": "protect",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": rules,
        **kw,
    }
    r = call(gh, tok, "POST", "/rulesets", json=body)
    assert r.status == 201, r.body
    return r.body  # type: ignore[no-any-return]


def required(*contexts: str, strict: bool = False, **extra: Any) -> dict[str, Any]:
    return {
        "type": "required_status_checks",
        "parameters": {
            "required_status_checks": [{"context": c, **extra} for c in contexts],
            "strict_required_status_checks_policy": strict,
        },
    }


def reviews_rule(count: int = 1, **kw: Any) -> dict[str, Any]:
    params = {
        "required_approving_review_count": count,
        "dismiss_stale_reviews_on_push": False,
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_review_thread_resolution": False,
        **kw,
    }
    return {"type": "pull_request", "parameters": params}


def merge(gh: FakeGitHubChecks, tok: str, n: int, **body: Any) -> dict[str, Any]:
    """Request an async merge, run it, and return the polled result."""
    first = call(gh, tok, "PUT", f"/pulls/{n}/merge-async", json=body)
    assert first.status == 202, first.body
    gh.settle()
    done = call(gh, tok, "GET", f"/pulls/{n}/merge-async/{first.body['details']['uuid']}")
    assert done.status == 200
    return done.body  # type: ignore[no-any-return]


def state_of(gh: FakeGitHubChecks, tok: str, n: int) -> str:
    call(gh, tok, "GET", f"/pulls/{n}")  # the first read only starts the computation
    return str(call(gh, tok, "GET", f"/pulls/{n}").body["mergeable_state"])


def with_workflow(gh: FakeGitHubChecks, text: str = WORKFLOW, name: str = "ci.yml") -> None:
    gh.push(REPO, "main", {f".github/workflows/{name}": text})


def dispatch(gh: FakeGitHubChecks, tok: str, wf: str = "ci.yml", **body: Any) -> Response:
    body.setdefault("ref", "main")
    return call(gh, tok, "POST", f"/actions/workflows/{wf}/dispatches", json=body)


# --- acceptance criteria ----------------------------------------------------------------------


class TestRequiredChecksBlock:
    """AC1: a required check pending blocks. https://docs.github.com/en/pull-requests/how-tos/
    merge-and-close-pull-requests/troubleshooting-required-status-checks (a check that is missing
    or pending is "Expected" and blocks)."""

    def test_a_required_check_that_has_not_reported_blocks_the_merge(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        assert state_of(gh, tok, 1) == "blocked"
        result = merge(gh, tok, 1, sha=head_of(pr))
        assert result["status"] == "failed"
        assert 'Required status check "ci" is expected.' in result["details"]["message"]
        assert result["details"]["message"].startswith("Repository rule violations found")
        assert gh.pulls(REPO)[0].merged is False

    @pytest.mark.parametrize("status", ["queued", "in_progress"])
    def test_a_pending_required_check_blocks_until_it_completes(
        self, gh: FakeGitHubChecks, tok: str, status: str
    ) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        run = check(gh, tok, head_of(pr), status=status)
        assert merge(gh, tok, 1)["status"] == "failed"
        done = call(gh, tok, "PATCH", f"/check-runs/{run['id']}", json={"conclusion": "success"})
        assert done.status == 200
        assert done.body["status"] == "completed"
        assert state_of(gh, tok, 1) == "clean"
        assert merge(gh, tok, 1)["status"] == "merged"

    def test_a_failed_required_check_blocks_with_its_own_message(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), conclusion="failure")
        assert 'Required status check "ci" is failing.' in merge(gh, tok, 1)["details"]["message"]

    def test_only_the_head_commits_checks_count(self, gh: FakeGitHubChecks, tok: str) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), conclusion="success")
        gh.push(REPO, "feat", {"more.txt": "y"})  # the old SHA's check does not carry over
        assert merge(gh, tok, 1)["status"] == "failed"

    def test_every_required_check_must_pass_and_each_failure_is_named(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [required("a", "b", "c")])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), "a", conclusion="success")
        check(gh, tok, head_of(pr), "b", conclusion="failure")
        found = {(v.kind, v.subject) for v in gh.protection(1)}
        assert found == {("check_failing", "b"), ("check_expected", "c")}

    def test_a_check_not_required_does_not_block(self, gh: FakeGitHubChecks, tok: str) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), "ci", conclusion="success")
        check(gh, tok, head_of(pr), "extra", conclusion="failure")
        assert merge(gh, tok, 1)["status"] == "merged"

    def test_the_latest_run_of_a_name_decides_and_a_rerun_can_pass(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), conclusion="failure")
        assert state_of(gh, tok, 1) == "blocked"
        check(gh, tok, head_of(pr), conclusion="success")
        assert state_of(gh, tok, 1) == "clean"

    def test_a_check_pinned_to_an_app_ignores_other_apps(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset:
        ``integration_id`` pins a required check to an app."""
        pr = open_pr(gh, tok)
        ruleset(gh, tok, [required("ci", integration_id=4242)])
        check(gh, tok, head_of(pr), conclusion="success")  # ours, not 4242
        assert [v.kind for v in gh.protection(1)] == ["check_expected"]
        gh.add_check_run(head_of(pr), "ci", app_id=4242)
        assert gh.protection(1) == []

    def test_a_strict_policy_blocks_a_head_that_is_behind_the_base(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [required("ci", strict=True)])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), conclusion="success")
        assert gh.protection(1) == []
        gh.push(REPO, "main", {"new.txt": "n"})
        assert [v.kind for v in gh.protection(1)] == ["not_up_to_date"]

    def test_a_ruleset_that_is_not_active_or_not_aimed_at_the_base_does_not_block(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        open_pr(gh, tok)
        ruleset(gh, tok, [required("ci")], enforcement="disabled", name="off")
        ruleset(gh, tok, [required("ci")], enforcement="evaluate", name="dry")
        ruleset(
            gh, tok, [required("ci")], name="elsewhere",
            conditions={"ref_name": {"include": ["refs/heads/release/*"], "exclude": []}},
        )  # fmt: skip
        assert gh.protection(1) == []
        assert merge(gh, tok, 1)["status"] == "merged"

    def test_an_admin_bypass_on_the_merge_request_skips_the_block(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """unsourced: pulls' ``bypass_rules`` applies to a ruleset block too."""
        ruleset(gh, tok, [required("ci")])
        open_pr(gh, tok)
        assert merge(gh, tok, 1, bypass_rules=True)["status"] == "merged"

    def test_a_scripted_block_and_a_ruleset_block_both_hold(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        pr = open_pr(gh, tok)
        gh.block_merge(1, "scripted")
        assert merge(gh, tok, 1)["details"]["message"] == "scripted"
        gh.block_merge(1, None)
        ruleset(gh, tok, [required("ci")])
        check(gh, tok, head_of(pr), conclusion="success")
        assert merge(gh, tok, 1)["status"] == "merged"


class TestNeutralPasses:
    """AC2: neutral passes. Skipped and neutral count as success for a required check:
    https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/about-status-checks#check-statuses-and-conclusions"""

    @pytest.mark.parametrize("conclusion", ["success", "neutral", "skipped"])
    def test_these_conclusions_satisfy_a_required_check(
        self, gh: FakeGitHubChecks, tok: str, conclusion: str
    ) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), conclusion=conclusion)
        assert gh.protection(1) == []
        assert state_of(gh, tok, 1) == "clean"
        assert merge(gh, tok, 1)["status"] == "merged"

    @pytest.mark.parametrize(
        "conclusion", ["failure", "cancelled", "timed_out", "action_required", "stale"]
    )
    def test_these_conclusions_do_not(
        self, gh: FakeGitHubChecks, tok: str, conclusion: str
    ) -> None:
        ruleset(gh, tok, [required("ci")])
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr), conclusion=conclusion)
        assert [v.kind for v in gh.protection(1)] == ["check_failing"]


class TestDispatchRunIdOnlyInTheResponse:
    """AC3. https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event
    and https://github.blog/changelog/2026-02-19-workflow-dispatch-api-now-returns-run-ids"""

    def test_the_run_id_is_in_the_response_when_asked_for(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        with_workflow(gh)
        r = dispatch(gh, tok, inputs={"target": "prod"}, return_run_details=True)
        assert r.status == 200
        run_id = r.body["workflow_run_id"]
        assert isinstance(run_id, int)
        assert r.body["run_url"].endswith(f"/actions/runs/{run_id}")
        assert r.body["html_url"].endswith(f"/actions/runs/{run_id}")
        got = call(gh, tok, "GET", f"/actions/runs/{run_id}")
        assert (got.status, got.body["event"], got.body["status"]) == (
            200, "workflow_dispatch", "queued",
        )  # fmt: skip

    def test_without_the_option_the_answer_is_204_and_has_no_run_id(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        with_workflow(gh)
        r = dispatch(gh, tok, inputs={"target": "prod"})
        assert (r.status, r.body) == (204, None)

    def test_a_crash_loses_the_run_id_but_the_run_exists(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """The response is lost after the dispatch applied. Nothing but the response carried the
        ID, so recovery is by listing runs (event, head_sha), as an adapter must."""
        with_workflow(gh)
        gh.fault_next("dispatch", "lose")
        with pytest.raises(TimeoutError):
            dispatch(gh, tok, inputs={"target": "prod"}, return_run_details=True)
        found = call(
            gh, tok, "GET", "/actions/workflows/ci.yml/runs",
            query={"event": "workflow_dispatch", "head_sha": str(gh.sha(REPO, "main"))},
        )  # fmt: skip
        assert found.status == 200
        assert found.body["total_count"] == 1
        assert found.body["workflow_runs"][0]["status"] == "queued"
        # a blind retry makes a second run: dispatch is not idempotent
        assert dispatch(gh, tok, inputs={"target": "prod"}).status == 204
        assert len(gh.workflow_runs(REPO)) == 2


# --- sources and permissions ------------------------------------------------------------------


def test_every_route_cites_docs_github_com_or_is_listed_as_unsourced() -> None:
    assert SOURCES
    for name, url in SOURCES.items():
        assert url.startswith("https://docs.github.com/"), name
    assert not set(SOURCES) & set(UNSOURCED)
    assert not set(SOURCES) & set(PULLS_SOURCES)
    assert set(SOURCES) | set(PULLS_SOURCES) | set(UNSOURCED) == set(FakeGitHubChecks.ROUTE_NAMES)


def test_every_route_of_the_table_has_a_handler_and_a_name_in_the_route_names() -> None:
    for _verb, _pattern, _op, name, _perms in FakeGitHubChecks._ROUTES:
        assert name in FakeGitHubChecks.ROUTE_NAMES, name
        assert hasattr(FakeGitHubChecks, "_h_" + name.replace("-", "_")), name


# https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps, read for
# each route (the page's wording: "Checks", "Metadata", "Administration", "Pull requests",
# "Actions").
DOCUMENTED: dict[str, tuple[str, str, str, str]] = {
    # route name: (method, path, permission, level)
    "create-check-run": ("POST", "/check-runs", "checks", "write"),
    "update-check-run": ("PATCH", "/check-runs/1", "checks", "write"),
    "get-check-run": ("GET", "/check-runs/1", "checks", "read"),
    "list-check-runs-for-ref": ("GET", "/commits/main/check-runs", "checks", "read"),
    "list-rulesets": ("GET", "/rulesets", "metadata", "read"),
    "get-ruleset": ("GET", "/rulesets/1", "metadata", "read"),
    "create-ruleset": ("POST", "/rulesets", "administration", "write"),
    "update-ruleset": ("PUT", "/rulesets/1", "administration", "write"),
    "delete-ruleset": ("DELETE", "/rulesets/1", "administration", "write"),
    "get-branch-rules": ("GET", "/rules/branches/main", "metadata", "read"),
    "list-reviews": ("GET", "/pulls/1/reviews", "pull_requests", "read"),
    "create-review": ("POST", "/pulls/1/reviews", "pull_requests", "write"),
    "dismiss-review": ("PUT", "/pulls/1/reviews/1/dismissals", "pull_requests", "write"),
    "dispatch-workflow": ("POST", "/actions/workflows/ci.yml/dispatches", "actions", "write"),
    "list-workflow-runs": ("GET", "/actions/workflows/ci.yml/runs", "actions", "read"),
    "list-repo-runs": ("GET", "/actions/runs", "actions", "read"),
    "get-run": ("GET", "/actions/runs/1", "actions", "read"),
}
ALL = {
    "checks": "write", "contents": "write", "issues": "write", "metadata": "read",
    "pull_requests": "write", "actions": "write", "administration": "write",
}  # fmt: skip


def test_the_permission_table_covers_every_route_of_this_fake() -> None:
    mine = {name for _v, _p, _o, name, _perms in FakeGitHubChecks._ROUTES} - set(PULLS_SOURCES)
    assert mine == set(DOCUMENTED)


@pytest.mark.parametrize("name", sorted(DOCUMENTED))
def test_each_route_needs_exactly_the_documented_permission(
    gh: FakeGitHubChecks, name: str
) -> None:
    method, path, perm, level = DOCUMENTED[name]
    held = {k: v for k, v in ALL.items() if k != perm}
    without = gh.mint(permissions=held)
    r = gh.request(method, R + path, without, json={})
    assert (r.status, r.body["message"]) == (403, "Resource not accessible by integration")
    if level == "write":  # read is not enough
        read = gh.mint(permissions={**held, perm: "read"})
        assert gh.request(method, R + path, read, json={}).status == 403
    exact = gh.mint(permissions={**held, perm: level})
    assert gh.request(method, R + path, exact, json={}).status != 403


def test_the_default_token_holds_actions_and_administration_too(gh: FakeGitHubChecks) -> None:
    """Departure (declared in server.py): this fake's installation also has these two, which the
    auth fake's does not list; the real App's permission set is D4-24's."""
    r = gh.create_installation_token(gh.app_jwt(), 200002)
    assert r.body["permissions"]["actions"] == "write"
    assert r.body["permissions"]["administration"] == "write"
    too_much = gh.create_installation_token(
        gh.app_jwt(), 200002, permissions={"workflows": "write"}
    )
    assert too_much.status == 422


def test_a_repository_outside_the_token_is_a_404_for_the_new_routes(gh: FakeGitHubChecks) -> None:
    narrow = gh.mint(repositories=["lib"])
    assert gh.request("GET", f"{R}/rulesets", narrow).status == 404
    assert gh.request("POST", f"{R}/check-runs", narrow, json={}).status == 404


# --- check runs -------------------------------------------------------------------------------


class TestCheckRuns:
    """https://docs.github.com/en/rest/checks/runs"""

    def test_create_then_get(self, gh: FakeGitHubChecks, tok: str) -> None:
        sha = str(gh.sha(REPO, "main"))
        run = check(
            gh, tok, sha, "ci", status="in_progress", external_id="e1",
            output={"title": "T", "summary": "S"}, details_url="https://ci.example/1",
        )  # fmt: skip
        assert (run["name"], run["head_sha"], run["status"], run["conclusion"]) == (
            "ci", sha, "in_progress", None,
        )  # fmt: skip
        assert run["app"]["id"] == int(APP_ID)  # created by this App
        assert run["output"]["title"] == "T"
        assert run["external_id"] == "e1"
        got = call(gh, tok, "GET", f"/check-runs/{run['id']}")
        assert (got.status, got.body["id"]) == (200, run["id"])
        assert call(gh, tok, "GET", "/check-runs/999999").status == 404

    def test_status_defaults_to_queued_and_a_conclusion_completes_it(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """Docs: ``conclusion`` ... "Providing conclusion will automatically set the status
        parameter to completed"."""
        sha = str(gh.sha(REPO, "main"))
        assert check(gh, tok, sha)["status"] == "queued"
        done = check(gh, tok, sha, "b", conclusion="neutral")
        assert (done["status"], done["conclusion"]) == ("completed", "neutral")
        assert done["completed_at"] is not None

    @pytest.mark.parametrize(
        ("body", "field"),
        [
            ({"name": 5}, "name"),
            ({"head_sha": 5}, "head_sha"),
            ({"status": "done"}, "status"),
            ({"conclusion": "great"}, "conclusion"),
            ({"output": {"title": "only"}}, "output"),
            ({"started_at": "yesterday"}, "started_at"),
            ({"external_id": 3}, "external_id"),
        ],
    )
    def test_bad_fields_are_422(
        self, gh: FakeGitHubChecks, tok: str, body: dict[str, Any], field: str
    ) -> None:
        payload = {"name": "ci", "head_sha": str(gh.sha(REPO, "main")), **body}
        r = call(gh, tok, "POST", "/check-runs", json=payload)
        assert r.status == 422, r.body
        assert field in str(r.body)

    def test_name_and_head_sha_are_required(self, gh: FakeGitHubChecks, tok: str) -> None:
        assert call(gh, tok, "POST", "/check-runs", json={"name": "ci"}).status == 422
        assert call(gh, tok, "POST", "/check-runs", json={"head_sha": "a" * 40}).status == 422

    def test_completed_needs_a_conclusion(self, gh: FakeGitHubChecks, tok: str) -> None:
        sha = str(gh.sha(REPO, "main"))
        for extra in ({"status": "completed"}, {"completed_at": "2026-01-01T00:00:00Z"}):
            r = call(gh, tok, "POST", "/check-runs", json={"name": "c", "head_sha": sha, **extra})
            assert r.status == 422, extra

    def test_an_unknown_commit_is_422(self, gh: FakeGitHubChecks, tok: str) -> None:
        """unsourced wording: GitHub's "No commit found for SHA"."""
        r = call(gh, tok, "POST", "/check-runs", json={"name": "c", "head_sha": "b" * 40})
        assert r.status == 422
        assert "No commit found for SHA" in r.body["message"]

    def test_update_changes_only_what_is_sent(self, gh: FakeGitHubChecks, tok: str) -> None:
        run = check(gh, tok, str(gh.sha(REPO, "main")), output={"title": "T", "summary": "S"})
        r = call(gh, tok, "PATCH", f"/check-runs/{run['id']}", json={"status": "in_progress"})
        assert (r.status, r.body["status"], r.body["output"]["title"]) == (200, "in_progress", "T")
        bad = call(gh, tok, "PATCH", f"/check-runs/{run['id']}", json={"conclusion": "nope"})
        assert bad.status == 422
        assert call(gh, tok, "PATCH", "/check-runs/999", json={}).status == 404

    def test_a_check_run_made_by_another_app_cannot_be_updated(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """unsourced: the docs say an app updates its own runs; the status code is ours."""
        theirs = gh.add_check_run(str(gh.sha(REPO, "main")), "ci", app_id=4242)
        r = call(gh, tok, "PATCH", f"/check-runs/{theirs}", json={"conclusion": "success"})
        assert r.status == 403

    def test_a_run_lists_the_open_pull_requests_on_its_commit(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        pr = open_pr(gh, tok)
        run = check(gh, tok, head_of(pr))
        assert [p["number"] for p in run["pull_requests"]] == [1]
        assert check(gh, tok, str(gh.sha(REPO, "main")))["pull_requests"] == []


class TestListCheckRunsForRef:
    """https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference"""

    def test_by_branch_sha_and_tag_style_refs(self, gh: FakeGitHubChecks, tok: str) -> None:
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr))
        for ref in ("feat", head_of(pr), "heads/feat"):
            r = call(gh, tok, "GET", f"/commits/{ref}/check-runs")
            assert (r.status, r.body["total_count"]) == (200, 1), ref
        assert call(gh, tok, "GET", "/commits/nope/check-runs").status == 422

    def test_latest_by_default_and_all_on_request(self, gh: FakeGitHubChecks, tok: str) -> None:
        sha = str(gh.sha(REPO, "main"))
        check(gh, tok, sha, "ci", conclusion="failure")
        second = check(gh, tok, sha, "ci", conclusion="success")
        latest = call(gh, tok, "GET", "/commits/main/check-runs").body
        assert [x["id"] for x in latest["check_runs"]] == [second["id"]]
        every = call(gh, tok, "GET", "/commits/main/check-runs", query={"filter": "all"}).body
        assert every["total_count"] == 2
        assert call(gh, tok, "GET", "/commits/main/check-runs", query={"filter": "x"}).status == 422

    def test_filters_by_name_status_and_app(self, gh: FakeGitHubChecks, tok: str) -> None:
        sha = str(gh.sha(REPO, "main"))
        check(gh, tok, sha, "a", conclusion="success")
        check(gh, tok, sha, "b", status="in_progress")
        gh.add_check_run(sha, "a", app_id=4242)

        def q(**kw: str) -> dict[str, Any]:
            return call(gh, tok, "GET", "/commits/main/check-runs", query=kw).body  # type: ignore[no-any-return]

        assert [x["name"] for x in q(check_name="b")["check_runs"]] == ["b"]
        assert q(status="in_progress")["total_count"] == 1
        assert q(status="completed")["total_count"] == 2
        assert q(app_id="4242")["total_count"] == 1
        assert call(gh, tok, "GET", "/commits/main/check-runs", query={"status": "x"}).status == 422

    def test_paging_keeps_every_filter_in_the_link_header(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        sha = str(gh.sha(REPO, "main"))
        for i in range(3):
            check(gh, tok, sha, f"n{i}", conclusion="success")
        r = call(
            gh, tok, "GET", "/commits/main/check-runs",
            query={"per_page": "2", "status": "completed", "filter": "all", "check_name": "n0"},
        )  # fmt: skip
        assert r.body["total_count"] == 1
        assert "link" not in r.headers
        r = call(
            gh, tok, "GET", "/commits/main/check-runs",
            query={"per_page": "2", "status": "completed", "filter": "all"},
        )  # fmt: skip
        assert r.body["total_count"] == 3
        assert len(r.body["check_runs"]) == 2
        link = r.headers["link"]
        assert 'rel="next"' in link
        for kept in ("status=completed", "filter=all", "per_page=2"):
            assert kept in link


# --- rulesets ---------------------------------------------------------------------------------


class TestRulesets:
    """https://docs.github.com/en/rest/repos/rules"""

    def test_create_get_list_update_delete(self, gh: FakeGitHubChecks, tok: str) -> None:
        made = ruleset(gh, tok, [required("ci")])
        assert made["source_type"] == "Repository"
        assert made["source"] == REPO
        assert made["enforcement"] == "active"
        assert made["target"] == "branch"
        got = call(gh, tok, "GET", f"/rulesets/{made['id']}")
        assert (got.status, got.body["rules"][0]["type"]) == (200, "required_status_checks")
        listed = call(gh, tok, "GET", "/rulesets").body
        assert [x["id"] for x in listed] == [made["id"]]
        assert "rules" not in listed[0]  # the list gives summaries
        put = call(gh, tok, "PUT", f"/rulesets/{made['id']}", json={"enforcement": "disabled"})
        assert (put.status, put.body["enforcement"], put.body["rules"]) == (
            200, "disabled", made["rules"],
        )  # fmt: skip
        assert call(gh, tok, "DELETE", f"/rulesets/{made['id']}").status == 204
        assert call(gh, tok, "GET", f"/rulesets/{made['id']}").status == 404
        assert call(gh, tok, "DELETE", f"/rulesets/{made['id']}").status == 404
        assert call(gh, tok, "PUT", "/rulesets/9", json={}).status == 404

    @pytest.mark.parametrize(
        "patch",
        [
            {"name": 3},
            {"name": None},
            {"enforcement": "maybe"},
            {"target": "file"},
            {"rules": "none"},
            {"rules": [{"type": "no_such_rule"}]},
            {"rules": [{"type": "required_status_checks", "parameters": {}}]},
            {
                "rules": [
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "required_status_checks": [{"integration_id": 1}],
                            "strict_required_status_checks_policy": False,
                        },
                    }
                ]
            },
            {
                "rules": [
                    {
                        "type": "required_status_checks",
                        "parameters": {"required_status_checks": [{"context": "ci"}]},
                    }
                ]
            },
            {
                "rules": [
                    {
                        "type": "pull_request",
                        "parameters": {
                            "required_approving_review_count": 11,
                            "dismiss_stale_reviews_on_push": False,
                            "require_code_owner_review": False,
                            "require_last_push_approval": False,
                            "required_review_thread_resolution": False,
                        },
                    }
                ]
            },
            {
                "rules": [
                    {"type": "pull_request", "parameters": {"required_approving_review_count": 1}}
                ]
            },
            {"conditions": {"ref_name": {"include": "main"}}},
            {"bypass_actors": "me"},
        ],
    )
    def test_a_malformed_ruleset_is_422(
        self, gh: FakeGitHubChecks, tok: str, patch: dict[str, Any]
    ) -> None:
        body: dict[str, Any] = {
            "name": "r", "enforcement": "active", "target": "branch",
            "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}}, "rules": [],
            **patch,
        }  # fmt: skip
        r = call(gh, tok, "POST", "/rulesets", json=body)
        assert r.status == 422, r.body

    def test_name_and_enforcement_are_required(self, gh: FakeGitHubChecks, tok: str) -> None:
        assert call(gh, tok, "POST", "/rulesets", json={"enforcement": "active"}).status == 422
        assert call(gh, tok, "POST", "/rulesets", json={"name": "x"}).status == 422

    def test_a_name_is_unique(self, gh: FakeGitHubChecks, tok: str) -> None:
        """unsourced wording; GitHub refuses a duplicate name."""
        ruleset(gh, tok, [])
        r = call(gh, tok, "POST", "/rulesets", json={"name": "protect", "enforcement": "active"})
        assert r.status == 422

    def test_rules_for_a_branch_lists_the_active_rules_that_apply(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch"""
        made = ruleset(gh, tok, [required("ci"), {"type": "deletion"}])
        ruleset(gh, tok, [{"type": "creation"}], enforcement="disabled", name="off")
        r = call(gh, tok, "GET", "/rules/branches/main")
        assert r.status == 200
        assert [x["type"] for x in r.body] == ["required_status_checks", "deletion"]
        assert r.body[0]["ruleset_id"] == made["id"]
        assert call(gh, tok, "GET", "/rules/branches/other").body == []

    def test_ref_patterns(self, gh: FakeGitHubChecks, tok: str) -> None:
        """Docs (creating-rulesets-for-a-repository): ``~DEFAULT_BRANCH``, ``~ALL``, fnmatch
        patterns where ``*`` stops at ``/`` and ``**`` does not, and exclude wins."""
        ruleset(
            gh, tok, [{"type": "deletion"}], name="a",
            conditions={"ref_name": {"include": ["refs/heads/rel/*"], "exclude": []}},
        )  # fmt: skip
        ruleset(
            gh, tok, [{"type": "creation"}], name="b",
            conditions={"ref_name": {"include": ["~ALL"], "exclude": ["refs/heads/tmp"]}},
        )  # fmt: skip
        ruleset(
            gh, tok, [{"type": "update"}], name="c",
            conditions={"ref_name": {"include": ["refs/heads/deep/**"], "exclude": []}},
        )  # fmt: skip

        def types(branch: str) -> list[str]:
            rows = call(gh, tok, "GET", f"/rules/branches/{branch}").body
            return sorted(x["type"] for x in rows)

        assert types("rel/1") == ["creation", "deletion"]
        assert types("rel/1/2") == ["creation"]
        assert types("tmp") == []
        assert types("deep/a/b") == ["creation", "update"]

    def test_listing_pages_keep_the_query(self, gh: FakeGitHubChecks, tok: str) -> None:
        for i in range(3):
            ruleset(gh, tok, [], name=f"r{i}")
        r = call(gh, tok, "GET", "/rulesets", query={"per_page": "2", "targets": "branch"})
        assert len(r.body) == 2
        assert "targets=branch" in r.headers["link"]


class TestRulesOnRefs:
    """unsourced for wording: GitHub answers 422 "Repository rule violations found" to a ref
    change a rule forbids; the rules themselves are the docs' (available-rules-for-rulesets)."""

    def test_deletion_rule_refuses_deleting_a_branch(self, gh: FakeGitHubChecks, tok: str) -> None:
        gh.push(REPO, "feat", {"f": "1"})
        ruleset(
            gh, tok, [{"type": "deletion"}],
            conditions={"ref_name": {"include": ["refs/heads/feat"], "exclude": []}},
        )  # fmt: skip
        r = call(gh, tok, "DELETE", "/git/refs/heads/feat")
        assert r.status == 422
        assert r.body["message"].startswith("Repository rule violations found")
        assert gh.sha(REPO, "feat") is not None

    def test_the_default_branch_still_refuses_deletion_and_a_missing_ref_is_the_old_error(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        assert call(gh, tok, "DELETE", "/git/refs/heads/main").status == 422
        ruleset(gh, tok, [{"type": "deletion"}], conditions={"ref_name": {"include": ["~ALL"]}})
        assert call(gh, tok, "DELETE", "/git/refs/heads/none").body["message"] == (
            "Reference does not exist"
        )

    def test_deleting_a_branch_with_a_pull_request_and_checks_does_not_crash(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        pr = open_pr(gh, tok)
        check(gh, tok, head_of(pr))
        ruleset(gh, tok, [required("ci"), reviews_rule(1)])
        assert call(gh, tok, "DELETE", "/git/refs/heads/feat").status == 204
        assert call(gh, tok, "GET", "/pulls/1").body["state"] == "closed"
        assert gh.protection(1) == []  # a closed PR has nothing left to block
        assert call(gh, tok, "GET", f"/commits/{head_of(pr)}/check-runs").status == 200
        assert call(gh, tok, "GET", "/pulls").status == 200

    def test_creation_update_and_non_fast_forward_rules(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        sha = str(gh.sha(REPO, "main"))
        ruleset(
            gh, tok, [{"type": "creation"}], name="c",
            conditions={"ref_name": {"include": ["refs/heads/locked/*"], "exclude": []}},
        )  # fmt: skip
        r = call(gh, tok, "POST", "/git/refs", json={"ref": "refs/heads/locked/x", "sha": sha})
        assert r.status == 422
        ok = call(gh, tok, "POST", "/git/refs", json={"ref": "refs/heads/free", "sha": sha})
        assert ok.status == 201
        gh.push(REPO, "nff", {"a": "1"})
        gh.push(REPO, "nff", {"a": "2"})
        ruleset(
            gh, tok, [{"type": "non_fast_forward"}], name="n",
            conditions={"ref_name": {"include": ["refs/heads/nff"], "exclude": []}},
        )  # fmt: skip
        back = {"sha": sha, "force": True}
        assert call(gh, tok, "PATCH", "/git/refs/heads/nff", json=back).status == 422
        gh.push(REPO, "frozen", {"a": "1"})
        ruleset(
            gh, tok, [{"type": "update"}], name="u",
            conditions={"ref_name": {"include": ["refs/heads/frozen"], "exclude": []}},
        )  # fmt: skip
        tip = str(gh.sha(REPO, "frozen"))
        assert call(gh, tok, "PATCH", "/git/refs/heads/frozen", json={"sha": tip}).status == 422

    def test_a_pull_request_rule_refuses_a_direct_merge_into_the_branch(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        gh.push(REPO, "side", {"s": "1"})
        ruleset(gh, tok, [reviews_rule(1)])
        r = call(gh, tok, "POST", "/merges", json={"base": "main", "head": "side"})
        assert r.status == 409
        assert r.body["message"].startswith("Repository rule violations")
        gh.push(REPO, "other", {"o": "1"})
        ok = call(gh, tok, "POST", "/merges", json={"base": "side", "head": "other"})
        assert ok.status == 201


# --- reviews ----------------------------------------------------------------------------------


def review(gh: FakeGitHubChecks, tok: str, n: int, **body: Any) -> Response:
    return call(gh, tok, "POST", f"/pulls/{n}/reviews", json=body)


class TestReviews:
    """https://docs.github.com/en/rest/pulls/reviews"""

    def test_create_and_list(self, gh: FakeGitHubChecks, tok: str) -> None:
        pr = open_pr(gh, tok)
        gh.set_author(1, "alice")
        r = review(gh, tok, 1, event="APPROVE", body="ok")
        assert r.status == 200, r.body
        assert (r.body["state"], r.body["commit_id"], r.body["user"]["login"]) == (
            "APPROVED", head_of(pr), "sto-bot",
        )  # fmt: skip
        listed = call(gh, tok, "GET", "/pulls/1/reviews").body
        assert [x["id"] for x in listed] == [r.body["id"]]
        assert call(gh, tok, "GET", "/pulls/9/reviews").status == 404

    def test_no_event_leaves_the_review_pending(self, gh: FakeGitHubChecks, tok: str) -> None:
        open_pr(gh, tok)
        gh.set_author(1, "alice")
        assert review(gh, tok, 1, body="draft").body["state"] == "PENDING"

    def test_request_changes_and_comment_need_a_body(self, gh: FakeGitHubChecks, tok: str) -> None:
        open_pr(gh, tok)
        gh.set_author(1, "alice")
        for event in ("REQUEST_CHANGES", "COMMENT"):
            assert review(gh, tok, 1, event=event).status == 422, event
            assert review(gh, tok, 1, event=event, body="because").status == 200, event

    def test_bad_types_are_422(self, gh: FakeGitHubChecks, tok: str) -> None:
        open_pr(gh, tok)
        gh.set_author(1, "alice")
        for body in (
            {"event": "LGTM"},
            {"body": 3},
            {"commit_id": 3},
            {"event": "APPROVE", "commit_id": "c" * 40},
        ):
            assert review(gh, tok, 1, **body).status == 422, body

    def test_an_author_cannot_approve_or_block_their_own_pull_request(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """unsourced wording: GitHub's "Can not approve your own pull request"."""
        open_pr(gh, tok)  # opened by the bot
        r = review(gh, tok, 1, event="APPROVE")
        assert r.status == 422
        assert "own pull request" in str(r.body)
        assert review(gh, tok, 1, event="REQUEST_CHANGES", body="x").status == 422
        assert review(gh, tok, 1, event="COMMENT", body="x").status == 200

    def test_dismiss(self, gh: FakeGitHubChecks, tok: str) -> None:
        open_pr(gh, tok)
        gh.add_review(1, "carol", "CHANGES_REQUESTED")
        rid = call(gh, tok, "GET", "/pulls/1/reviews").body[0]["id"]
        url = f"/pulls/1/reviews/{rid}/dismissals"
        assert call(gh, tok, "PUT", url, json={}).status == 422  # message is required
        r = call(gh, tok, "PUT", url, json={"message": "stale"})
        assert (r.status, r.body["state"]) == (200, "DISMISSED")
        assert call(gh, tok, "PUT", url, json={"message": "again"}).status == 422
        assert (
            call(gh, tok, "PUT", "/pulls/1/reviews/99/dismissals", json={"message": "m"}).status
            == 404
        )


class TestApprovalsDecideMergeability:
    def test_a_required_approval_blocks_until_a_writer_approves(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [reviews_rule(1)])
        open_pr(gh, tok)
        assert state_of(gh, tok, 1) == "blocked"
        msg = merge(gh, tok, 1)["details"]["message"]
        assert "At least 1 approving review is required by reviewers with write access." in msg
        gh.add_review(1, "stranger", "APPROVED", writer=False)  # no write access: does not count
        assert [v.kind for v in gh.protection(1)] == ["approvals_missing"]
        gh.add_review(1, "carol", "APPROVED")
        assert gh.protection(1) == []
        assert merge(gh, tok, 1)["status"] == "merged"

    def test_two_approvals_are_two(self, gh: FakeGitHubChecks, tok: str) -> None:
        ruleset(gh, tok, [reviews_rule(2)])
        open_pr(gh, tok)
        gh.add_review(1, "carol", "APPROVED")
        gh.add_review(1, "carol", "APPROVED")  # the same person twice is one
        assert "2 approving reviews" in gh.protection(1)[0].message
        gh.add_review(1, "dave", "APPROVED")
        assert gh.protection(1) == []

    def test_a_later_review_by_the_same_person_replaces_the_earlier(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [reviews_rule(1)])
        open_pr(gh, tok)
        gh.add_review(1, "carol", "APPROVED")
        gh.add_review(1, "carol", "CHANGES_REQUESTED")
        assert {v.kind for v in gh.protection(1)} == {"approvals_missing", "changes_requested"}
        gh.add_review(1, "carol", "COMMENTED")  # a comment does not lift it
        assert "changes_requested" in {v.kind for v in gh.protection(1)}
        gh.add_review(1, "carol", "APPROVED")
        assert gh.protection(1) == []

    def test_changes_requested_blocks_even_with_no_approvals_required(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [reviews_rule(0)])
        open_pr(gh, tok)
        assert gh.protection(1) == []
        gh.add_review(1, "carol", "CHANGES_REQUESTED")
        assert [v.kind for v in gh.protection(1)] == ["changes_requested"]

    def test_stale_approvals_are_dropped_only_when_the_rule_says_so(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [reviews_rule(1, dismiss_stale_reviews_on_push=True)])
        open_pr(gh, tok)
        gh.add_review(1, "carol", "APPROVED")
        gh.push(REPO, "feat", {"again.txt": "z"})
        assert [v.kind for v in gh.protection(1)] == ["approvals_missing"]
        state = call(gh, tok, "GET", "/pulls/1/reviews").body[0]["state"]
        assert state == "DISMISSED"

    def test_stale_approvals_stay_when_the_rule_does_not_dismiss(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [reviews_rule(1)])
        open_pr(gh, tok)
        gh.add_review(1, "carol", "APPROVED")
        gh.push(REPO, "feat", {"again.txt": "z"})
        assert gh.protection(1) == []


# --- workflow dispatch and runs ---------------------------------------------------------------


class TestDispatch:
    """https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event"""

    def test_by_file_name_or_numeric_id_with_inputs(self, gh: FakeGitHubChecks, tok: str) -> None:
        with_workflow(gh)
        first = dispatch(gh, tok, inputs={"target": "prod"}, return_run_details=True)
        run = call(gh, tok, "GET", f"/actions/runs/{first.body['workflow_run_id']}").body
        wf_id = run["workflow_id"]
        assert run["path"] == ".github/workflows/ci.yml"
        assert run["name"] == "CI"
        assert run["head_branch"] == "main"
        assert run["head_sha"] == gh.sha(REPO, "main")
        second = dispatch(gh, tok, str(wf_id), inputs={"target": "staging", "note": "n"})
        assert second.status == 204
        assert [r.inputs for r in gh.workflow_runs(REPO)] == [
            {"target": "prod", "note": "none"},
            {"target": "staging", "note": "n"},
        ]

    def test_it_runs_the_file_at_the_ref(self, gh: FakeGitHubChecks, tok: str) -> None:
        with_workflow(gh)
        gh.push(REPO, "topic", {".github/workflows/ci.yml": PUSH_ONLY})
        r = dispatch(gh, tok, ref="topic")
        assert r.status == 422
        assert "workflow_dispatch" in r.body["message"]
        gh.push(REPO, "topic", {".github/workflows/ci.yml": WORKFLOW})
        run = dispatch(gh, tok, ref="refs/heads/topic", inputs={"target": "prod"},
                       return_run_details=True)  # fmt: skip
        assert run.status == 200
        assert gh.workflow_runs(REPO)[0].head_branch == "topic"

    def test_the_workflow_must_exist_on_the_default_branch(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch:
        the event triggers only if the workflow file is on the default branch."""
        gh.push(REPO, "feat", {".github/workflows/new.yml": WORKFLOW})
        assert dispatch(gh, tok, "new.yml", ref="feat", inputs={"target": "x"}).status == 404
        with_workflow(gh)
        assert dispatch(gh, tok, "missing.yml").status == 404
        assert dispatch(gh, tok, "999999").status == 404

    @pytest.mark.parametrize(
        ("body", "needle"),
        [
            ({"inputs": {"target": "prod", "bogus": "1"}}, "Unexpected inputs"),
            ({"inputs": {}}, "Required input 'target'"),
            ({"inputs": {"target": "dev"}}, "not in the list of allowed values"),
            ({"ref": "nope", "inputs": {"target": "prod"}}, "No ref found for"),
            ({"inputs": {"target": ["prod"]}}, "target"),
            ({"inputs": "x"}, "inputs"),
            ({"inputs": {f"k{i}": "v" for i in range(26)}}, "more than 25"),
            ({"ref": 5}, "ref"),
            ({"inputs": {"target": "prod"}, "return_run_details": "yes"}, "return_run_details"),
        ],
    )
    def test_a_bad_dispatch_is_422_and_starts_nothing(
        self, gh: FakeGitHubChecks, tok: str, body: dict[str, Any], needle: str
    ) -> None:
        with_workflow(gh)
        r = dispatch(gh, tok, **body)
        assert r.status == 422, r.body
        assert needle in str(r.body), r.body
        assert gh.workflow_runs(REPO) == []

    def test_ref_is_required(self, gh: FakeGitHubChecks, tok: str) -> None:
        with_workflow(gh)
        r = call(gh, tok, "POST", "/actions/workflows/ci.yml/dispatches", json={})
        assert r.status == 422

    def test_a_workflow_without_the_trigger_is_422(self, gh: FakeGitHubChecks, tok: str) -> None:
        with_workflow(gh, PUSH_ONLY, "push.yml")
        r = dispatch(gh, tok, "push.yml")
        assert r.status == 422
        assert "workflow_dispatch" in r.body["message"]

    def test_a_dispatch_creates_a_check_run_per_job_on_the_ref_head(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """unsourced: Actions reports each job as a check run (names: the job's ``name`` or its
        key) under the GitHub Actions app."""
        with_workflow(gh)
        dispatch(gh, tok, inputs={"target": "prod"})
        runs = call(gh, tok, "GET", "/commits/main/check-runs").body["check_runs"]
        assert sorted(x["name"] for x in runs) == ["Lint code", "build"]
        assert {x["app"]["id"] for x in runs} == {int(ACTIONS_APP_ID)}

    def test_a_dispatched_workflow_can_satisfy_a_required_check(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        """Composition with D4-19: required checks decide the merge, a run's jobs report them."""
        gh.push(REPO, "feat", {".github/workflows/ci.yml": WORKFLOW})
        gh.push(REPO, "main", {".github/workflows/ci.yml": WORKFLOW})
        ruleset(gh, tok, [required("build")])
        open_pr(gh, tok)
        r = dispatch(gh, tok, ref="feat", inputs={"target": "prod"}, return_run_details=True)
        run_id = r.body["workflow_run_id"]
        assert merge(gh, tok, 1)["status"] == "failed"  # queued: not yet
        gh.start_run(run_id)
        assert gh.protection(1)[0].kind == "check_expected"
        gh.complete_run(run_id, "success")
        assert merge(gh, tok, 1)["status"] == "merged"


class TestWorkflowRuns:
    """https://docs.github.com/en/rest/actions/workflow-runs"""

    def _three(self, gh: FakeGitHubChecks, tok: str) -> list[int]:
        with_workflow(gh)
        gh.push(REPO, "topic", {"t": "1"})
        ids = []
        for ref in ("main", "topic", "main"):
            r = dispatch(gh, tok, ref=ref, inputs={"target": "prod"}, return_run_details=True)
            ids.append(r.body["workflow_run_id"])
        return ids

    def test_filters(self, gh: FakeGitHubChecks, tok: str) -> None:
        ids = self._three(gh, tok)
        gh.complete_run(ids[0], "failure")

        def q(**kw: str) -> dict[str, Any]:
            return call(gh, tok, "GET", "/actions/runs", query=kw).body  # type: ignore[no-any-return]

        assert q()["total_count"] == 3
        assert {x["id"] for x in q(branch="main")["workflow_runs"]} == {ids[0], ids[2]}
        assert q(event="push")["total_count"] == 0
        assert q(event="workflow_dispatch")["total_count"] == 3
        assert q(status="queued")["total_count"] == 2
        assert q(status="completed")["total_count"] == 1
        assert q(status="failure")["total_count"] == 1  # a conclusion is accepted as status
        assert q(head_sha=str(gh.sha(REPO, "topic")))["total_count"] == 1
        assert q(actor="sto-bot")["total_count"] == 3
        assert q(actor="nobody")["total_count"] == 0
        day = q()["workflow_runs"][0]["created_at"][:10]
        assert q(created=f">={day}")["total_count"] == 3
        assert q(created=f">{day}")["total_count"] == 0
        assert q(created=f"<{day}")["total_count"] == 0
        assert q(created=f"{day}..{day}")["total_count"] == 3
        assert q(created="1999-01-01..1999-12-31")["total_count"] == 0
        assert q(created=day)["total_count"] == 3

    def test_listing_a_workflow_scopes_to_it_and_newest_comes_first(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ids = self._three(gh, tok)
        with_workflow(gh, WORKFLOW, "other.yml")
        dispatch(gh, tok, "other.yml", inputs={"target": "prod"})
        r = call(gh, tok, "GET", "/actions/workflows/ci.yml/runs").body
        assert [x["id"] for x in r["workflow_runs"]] == list(reversed(ids))
        assert [x["run_number"] for x in r["workflow_runs"]] == [3, 2, 1]
        assert call(gh, tok, "GET", "/actions/workflows/none.yml/runs").status == 404

    def test_bad_filters_are_422_and_paging_keeps_them(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        self._three(gh, tok)
        assert call(gh, tok, "GET", "/actions/runs", query={"status": "bogus"}).status == 422
        r = call(
            gh, tok, "GET", "/actions/runs", query={"per_page": "2", "event": "workflow_dispatch"}
        )
        assert len(r.body["workflow_runs"]) == 2
        assert "event=workflow_dispatch" in r.headers["link"]

    def test_get_a_run(self, gh: FakeGitHubChecks, tok: str) -> None:
        ids = self._three(gh, tok)
        r = call(gh, tok, "GET", f"/actions/runs/{ids[0]}")
        assert (r.status, r.body["status"], r.body["conclusion"]) == (200, "queued", None)
        gh.start_run(ids[0])
        assert call(gh, tok, "GET", f"/actions/runs/{ids[0]}").body["status"] == "in_progress"
        gh.complete_run(ids[0], "cancelled")
        done = call(gh, tok, "GET", f"/actions/runs/{ids[0]}").body
        assert (done["status"], done["conclusion"]) == ("completed", "cancelled")
        assert call(gh, tok, "GET", "/actions/runs/1").status == 404


# --- composition with the pulls fake ----------------------------------------------------------


def test_the_pulls_fake_behaviour_is_unchanged_without_rules(
    gh: FakeGitHubChecks, tok: str
) -> None:
    open_pr(gh, tok)
    assert state_of(gh, tok, 1) == "clean"
    assert merge(gh, tok, 1)["status"] == "merged"
    assert gh.protection(1) == []


def test_a_merge_queue_request_is_blocked_by_a_required_check_too(
    gh: FakeGitHubChecks, tok: str
) -> None:
    gh.enable_merge_queue(REPO, "main")
    ruleset(gh, tok, [required("ci")])
    pr = open_pr(gh, tok)
    assert merge(gh, tok, 1)["status"] == "failed"
    check(gh, tok, head_of(pr), conclusion="neutral")
    assert merge(gh, tok, 1)["status"] == "enqueued"


def test_list_pulls_shows_blocked_state_too(gh: FakeGitHubChecks, tok: str) -> None:
    ruleset(gh, tok, [required("ci")])
    open_pr(gh, tok)
    call(gh, tok, "GET", "/pulls/1")  # a GET of the PR starts the (asynchronous) computation
    assert call(gh, tok, "GET", "/pulls").body[0]["mergeable_state"] == "blocked"


class TestEdgesFoundByMutation:
    """Each of these pins a behaviour a mutation pass showed nothing else did."""

    def test_a_tag_ruleset_does_not_govern_branches_and_governs_tags(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        sha = str(gh.sha(REPO, "main"))
        ruleset(
            gh, tok, [{"type": "deletion"}], target="tag", name="tags",
            conditions={"ref_name": {"include": ["~ALL"], "exclude": []}},
        )  # fmt: skip
        gh.push(REPO, "feat", {"f": "1"})
        assert call(gh, tok, "GET", "/rules/branches/feat").body == []
        assert call(gh, tok, "DELETE", "/git/refs/heads/feat").status == 204
        made = call(gh, tok, "POST", "/git/refs", json={"ref": "refs/tags/v1", "sha": sha})
        assert made.status == 201
        assert call(gh, tok, "DELETE", "/git/refs/tags/v1").status == 422

    def test_a_force_update_that_leaves_the_head_alone_keeps_the_approval(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [reviews_rule(1, dismiss_stale_reviews_on_push=True)])
        pr = open_pr(gh, tok)
        gh.add_review(1, "carol", "APPROVED")
        same = call(
            gh, tok, "PATCH", "/git/refs/heads/feat", json={"sha": head_of(pr), "force": True}
        )
        assert same.status == 200
        assert gh.protection(1) == []

    def test_creating_an_existing_ref_under_a_creation_rule_is_the_ordinary_error(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [{"type": "creation"}], conditions={"ref_name": {"include": ["~ALL"]}})
        sha = str(gh.sha(REPO, "main"))
        r = call(gh, tok, "POST", "/git/refs", json={"ref": "refs/heads/main", "sha": sha})
        assert r.body["message"] == "Reference already exists"

    def test_someone_elses_pending_review_is_not_listed(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        open_pr(gh, tok)
        gh.add_review(1, "carol", "PENDING")
        gh.add_review(1, "carol", "COMMENTED")
        states = [x["state"] for x in call(gh, tok, "GET", "/pulls/1/reviews").body]
        assert states == ["COMMENTED"]

    def test_a_closed_pull_request_has_no_protection_failures(
        self, gh: FakeGitHubChecks, tok: str
    ) -> None:
        ruleset(gh, tok, [required("ci")])
        open_pr(gh, tok)
        assert [v.kind for v in gh.protection(1)] == ["check_expected"]
        call(gh, tok, "PATCH", "/pulls/1", json={"state": "closed"})
        assert gh.protection(1) == []
