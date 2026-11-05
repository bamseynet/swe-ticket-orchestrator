"""D6-09 review pass 1: each case here answers one finding. Specs read: the v3 and Agile OpenAPI
documents (``IssueUpdateDetails``, ``WebhookRegistrationDetails``, ``WebhookDetails``, the sprint
update notes, the board and sprint query parameters)."""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from fakes.jira.issues import BASIC, FakeJiraIssues
from fakes.jira.workflow import FakeJiraWebhooks, FakeJiraWorkflow

API, AGILE = "/rest/api/3", "/rest/agile/1.0"
DATES = {"startDate": "2026-01-05T09:00:00.000Z", "endDate": "2026-01-19T09:00:00.000Z"}
ADF = {
    "type": "doc",
    "version": 1,
    "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Bug has been fixed"}]}],
}


@pytest.fixture
def jira() -> FakeJiraWorkflow:
    return FakeJiraWorkflow()


def api(jira: FakeJiraWorkflow, method: str, path: str, **kw: Any) -> Any:
    kw.setdefault("auth", BASIC)
    return jira.request(method, API + path, **kw)


def agile(jira: FakeJiraWorkflow, method: str, path: str, **kw: Any) -> Any:
    kw.setdefault("auth", BASIC)
    return jira.request(method, AGILE + path, **kw)


def app(jira: FakeJiraWorkflow) -> str:
    return jira.new_bearer()


def register(jira: FakeJiraWorkflow, url: str = "https://r.example.test/h", **hook: Any) -> Any:
    hook = {"events": ["jira:issue_updated"], "jqlFilter": "project = SYN", **hook}
    body = {"url": url, "webhooks": [hook]}
    return jira.request("POST", f"{API}/webhook", auth=app(jira), json=body)


# --- the reach-ins into D6-01 ----------------------------------------------------------------


def test_every_private_name_relied_on_exists_on_the_parent() -> None:
    """A rename in D6-01 must fail here, loudly, rather than somewhere deep in a Jira test."""
    from fakes.jira.issues import server as parent

    for name in (
        "_UNKNOWN_FIELD",
        "_err",
        "_errors",
        "_flag",
        "_int",
        "_iso",
        "_not_modelled",
        "HOST",
        "SOURCES",
        "Headers",
        "Response",
        "ACCOUNT_ID",
        "PROJECTS",
    ):
        assert hasattr(parent, name), name
    for name in (
        "_visible",
        "_touch",
        "_route",
        "_select",
        "_field_list",
        "_add_comment",
        "_comment_body_problem",
        "request",
        "add_status",
        "add_issue",
    ):
        assert callable(getattr(FakeJiraIssues, name)), name
    seeded = FakeJiraIssues()
    seeded.add_issue(summary="x")
    for attr in ("_issues", "_by_id", "_statuses", "_comments", "_denied"):
        assert hasattr(seeded, attr), attr
    assert "SYN-1" in seeded._issues
    assert "to do" in seeded._statuses
    # the dispatch the subclass leans on: request() calls self._<op>(*args, params=, body=)
    assert issubclass(FakeJiraWorkflow, FakeJiraIssues)
    route = FakeJiraIssues._route("GET", "/rest/api/3/issue/SYN-1")
    assert route == ("get_issue", ("SYN-1",))
    assert callable(FakeJiraIssues._get_issue)


# --- 1: seeded status shape --------------------------------------------------------------------


def test_seeded_status_has_the_workflow_category_and_the_transition_shape(
    jira: FakeJiraWorkflow,
) -> None:
    seeded = jira.add_issue(summary="a", project="OTH", status="In Review")
    expected = {"key": "indeterminate", "id": 4, "name": "In Progress"}
    assert seeded["fields"]["status"]["statusCategory"] == expected
    other = jira.add_issue(summary="b", project="OTH")
    api(jira, "POST", f"/issue/{other['key']}/transitions", json={"transition": {"id": "21"}})
    moved = api(jira, "GET", f"/issue/{other['key']}").body["fields"]["status"]
    assert moved["statusCategory"] == expected
    assert set(seeded["fields"]["status"]) == set(moved)


def test_seeded_default_statuses_get_their_categories(jira: FakeJiraWorkflow) -> None:
    done = jira.add_issue(summary="a", status="Done")["fields"]["status"]
    assert done["statusCategory"] == {"key": "done", "id": 3, "name": "Done"}
    unknown = jira.add_issue(summary="b", project="NEW", status="Weird")["fields"]["status"]
    assert unknown["statusCategory"]["key"] == "new"


# --- 2: comment on a transition ----------------------------------------------------------------


def test_spec_example_comment_add_on_a_transition(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", status="In Progress")["key"]
    body = {
        "transition": {"id": "21"},
        "fields": {"resolution": {"name": "Done"}},
        "update": {"comment": [{"add": {"body": ADF}}]},
    }
    assert api(jira, "POST", f"/issue/{key}/transitions", json=body).status == 204
    comments = api(jira, "GET", f"/issue/{key}/comment").body["comments"]
    assert [c["body"] for c in comments] == [ADF]
    assert api(jira, "GET", f"/issue/{key}").body["fields"]["status"]["name"] == "Done"


@pytest.mark.parametrize(
    "ops",
    [
        [{"add": {"body": "plain text"}}],
        [{"add": {}}],
        [{"edit": {"body": ADF}}],
        [{"add": {"body": ADF, "visibility": {"type": "role", "value": "x"}}}],
        "add",
        [],
        [{"add": {"body": ADF}, "remove": {}}],
    ],
)
def test_a_bad_comment_leaves_the_issue_untouched(jira: FakeJiraWorkflow, ops: Any) -> None:
    key = jira.add_issue(summary="a", status="In Progress")["key"]
    body = {
        "transition": {"id": "21"},
        "fields": {"resolution": {"name": "Done"}},
        "update": {"comment": ops},
    }
    r = api(jira, "POST", f"/issue/{key}/transitions", json=body)
    assert r.status == 400
    assert api(jira, "GET", f"/issue/{key}").body["fields"]["status"]["name"] == "In Progress"
    assert api(jira, "GET", f"/issue/{key}/comment").body["comments"] == []


def test_comment_is_an_update_operation_not_a_field(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    r = api(
        jira,
        "POST",
        f"/issue/{key}/transitions",
        json={"transition": {"id": "11"}, "fields": {"comment": ADF}},
    )
    assert r.status == 400
    assert "comment" in r.body["errors"]


# --- 3 and 4: sprint states, dates, goal -------------------------------------------------------

_STATES = ("future", "active", "closed")


@pytest.mark.parametrize("old", _STATES)
@pytest.mark.parametrize("new", _STATES)
def test_every_sprint_state_pair(jira: FakeJiraWorkflow, old: str, new: str) -> None:
    board = jira.add_board("B")
    sprint = jira.add_sprint(board, "S", old)
    body = {"state": new, **DATES}
    r = agile(jira, "POST", f"/sprint/{sprint}", json=body)
    allowed = {("future", "active"), ("active", "closed")} | {(s, s) for s in _STATES}
    assert r.status == (200 if (old, new) in allowed else 400), (old, new, r.body)
    now = agile(jira, "GET", f"/sprint/{sprint}").body["state"]
    assert now == (new if (old, new) in allowed else old)


def test_starting_needs_both_dates(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("B")
    sprint = jira.add_sprint(board, "S")
    for body in (
        {"state": "active"},
        {"state": "active", "startDate": DATES["startDate"]},
        {"state": "active", "endDate": DATES["endDate"]},
    ):
        assert agile(jira, "POST", f"/sprint/{sprint}", json=body).status == 400
    assert agile(jira, "GET", f"/sprint/{sprint}").body["state"] == "future"
    r = agile(jira, "POST", f"/sprint/{sprint}", json={"state": "active", **DATES})
    assert r.status == 200
    assert r.body["startDate"] == DATES["startDate"]
    assert r.body["endDate"] == DATES["endDate"]


def test_dates_set_earlier_count_for_starting(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("B")
    sprint = jira.add_sprint(board, "S", start_date=DATES["startDate"], end_date=DATES["endDate"])
    assert agile(jira, "POST", f"/sprint/{sprint}", json={"state": "active"}).status == 200
    plain = jira.add_sprint(jira.add_board("C"), "T")
    assert agile(jira, "POST", f"/sprint/{plain}", json=DATES).status == 200  # dates alone
    assert agile(jira, "POST", f"/sprint/{plain}", json={"state": "active"}).status == 200


def test_goal_name_and_dates_are_accepted_and_validated(jira: FakeJiraWorkflow) -> None:
    sprint = jira.add_sprint(jira.add_board("B"), "S")
    r = agile(jira, "POST", f"/sprint/{sprint}", json={"goal": "ship", "name": "S2", **DATES})
    assert r.status == 200
    assert (r.body["goal"], r.body["name"]) == ("ship", "S2")
    for bad in (
        {"startDate": "yesterday"},
        {"goal": 5},
        {"name": ""},
        {"endDate": 7},
        {"completeDate": "2026-01-01T00:00:00.000Z"},
        {"id": 1},
        {"bogus": 1},
    ):
        assert agile(jira, "POST", f"/sprint/{sprint}", json=bad).status == 400, bad


def test_a_closed_sprint_changes_only_name_and_goal(jira: FakeJiraWorkflow) -> None:
    sprint = jira.add_sprint(jira.add_board("B"), "S", "closed")
    before = agile(jira, "GET", f"/sprint/{sprint}").body
    r = agile(
        jira,
        "POST",
        f"/sprint/{sprint}",
        json={"name": "N", "goal": "G", "startDate": "2020-01-01T00:00:00.000Z"},
    )
    assert r.status == 200
    assert (r.body["name"], r.body["goal"]) == ("N", "G")
    assert r.body["startDate"] == before["startDate"]  # spec: other changes are ignored


def test_closing_sets_the_complete_date(jira: FakeJiraWorkflow) -> None:
    sprint = jira.add_sprint(jira.add_board("B"), "S", "active")
    jira.now += 3600
    r = agile(jira, "POST", f"/sprint/{sprint}", json={"state": "closed"})
    assert r.body["completeDate"].startswith("2026-01-01T01:00:00")


def test_seeding_helper_matches_the_api(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("B")
    jira.add_sprint(board, "A", "active")
    with pytest.raises(ValueError, match="active"):
        jira.add_sprint(board, "B", "active")
    with pytest.raises(ValueError, match="board"):
        jira.add_sprint(999, "X")
    with pytest.raises(ValueError, match="state"):
        jira.add_sprint(board, "X", "bogus")
    with pytest.raises(ValueError, match="sprints"):
        jira.add_sprint(jira.add_board("K", "kanban"), "X")
    parallel = FakeJiraWorkflow(parallel_sprints=True)
    pb = parallel.add_board("B")
    parallel.add_sprint(pb, "A", "active")
    parallel.add_sprint(pb, "B", "active")
    s = jira.add_sprint(board, "C", "closed")  # a closed one beside the active one is fine
    assert "completeDate" in agile(jira, "GET", f"/sprint/{s}").body


# --- 5: board project id -----------------------------------------------------------------------


def test_board_location_uses_the_projects_real_id(jira: FakeJiraWorkflow) -> None:
    syn, oth = jira.add_board("A", project="SYN"), jira.add_board("B", project="OTH")
    assert agile(jira, "GET", f"/board/{syn}").body["location"]["projectId"] == 10000
    assert agile(jira, "GET", f"/board/{oth}").body["location"]["projectId"] == 10100
    by_id = agile(jira, "GET", "/board", params={"projectKeyOrId": "10100"}).body["values"]
    assert [b["name"] for b in by_id] == ["B"]
    by_key = agile(jira, "GET", "/board", params={"projectKeyOrId": "SYN"}).body["values"]
    assert [b["name"] for b in by_key] == ["A"]


# --- 6: unmodelled parameters ------------------------------------------------------------------


def test_unmodelled_agile_parameters_are_refused(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("A")
    sprint = jira.add_sprint(board, "S", "active")
    key = jira.add_issue(summary="a")["key"]
    cases = [
        ("/board", {"name": "A"}),
        ("/board", {"expand": "x"}),
        ("/board", {"orderBy": "name"}),
        (f"/board/{board}", {"expand": "x"}),
        (f"/board/{board}/sprint", {"bogus": 1}),
        (f"/sprint/{sprint}", {"x": 1}),
        (f"/sprint/{sprint}/issue", {"jql": "key = SYN-1"}),
        (f"/sprint/{sprint}/issue", {"validateQuery": "false"}),
        (f"/issue/{key}", {"expand": "names"}),
        (f"/issue/{key}", {"updateHistory": "true"}),
    ]
    for path, params in cases:
        r = agile(jira, "GET", path, params=params)
        assert r.status == 400, (path, params)
        assert "Not modelled" in r.body["errorMessages"][0]


def test_unmodelled_parameters_elsewhere_are_refused(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    assert api(jira, "GET", f"/issue/{key}/transitions", params={"bogus": 1}).status == 400
    assert (
        api(
            jira,
            "POST",
            f"/issue/{key}/transitions",
            params={"x": 1},
            json={"transition": {"id": "11"}},
        ).status
        == 400
    )
    assert jira.request("GET", f"{API}/webhook", auth=app(jira), params={"x": 1}).status == 400
    sprint = jira.add_sprint(jira.add_board("B"), "S")
    assert agile(jira, "POST", f"/sprint/{sprint}", params={"x": 1}, json={}).status == 400


def test_the_agile_issue_honours_the_fields_parameter(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    r = agile(jira, "GET", f"/issue/{key}", params={"fields": "summary,sprint"})
    assert set(r.body["fields"]) == {"summary", "sprint"}


# --- 7 and 8: webhook registration -------------------------------------------------------------


def results(r: Any) -> list[dict[str, Any]]:
    assert r.status == 200, r.body
    return list(r.body["webhookRegistrationResult"])


def test_only_a_single_url_per_app(jira: FakeJiraWorkflow) -> None:
    (first,) = results(register(jira, "https://a.example.test/h"))
    assert "createdWebhookId" in first
    (second,) = results(register(jira, "https://b.example.test/h"))
    assert "createdWebhookId" not in second
    assert second["errors"]
    assert "createdWebhookId" in results(register(jira, "https://a.example.test/h"))[0]
    jira.clear_webhooks()  # all deleted: the app may choose a new URL
    assert "createdWebhookId" in results(register(jira, "https://b.example.test/h"))[0]


@pytest.mark.parametrize(
    "event", ["jira:issue_update", "issue_created", "", 5, "JIRA:ISSUE_CREATED"]
)
def test_event_names_are_checked_against_the_enum(jira: FakeJiraWorkflow, event: Any) -> None:
    r = register(jira, events=[event])
    assert r.status == 400
    assert jira.request("GET", f"{API}/webhook", auth=app(jira)).body["values"] == []


def test_every_documented_event_is_accepted(jira: FakeJiraWorkflow) -> None:
    events = ["jira:issue_created", "comment_created", "sprint_started", "jira:version_released"]
    assert "createdWebhookId" in results(register(jira, events=events))[0]


def test_unknown_keys_are_refused(jira: FakeJiraWorkflow) -> None:
    extra_hook = register(jira, extra=1)
    assert extra_hook.status == 400
    body = {
        "url": "https://r.example.test/h",
        "bogus": 1,
        "webhooks": [{"events": ["jira:issue_updated"], "jqlFilter": "project = SYN"}],
    }
    assert jira.request("POST", f"{API}/webhook", auth=app(jira), json=body).status == 400


# --- 9: paging ---------------------------------------------------------------------------------


def test_max_results_zero_is_refused_everywhere(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("A")
    for path in ("/board", f"/board/{board}/sprint"):
        assert agile(jira, "GET", path, params={"maxResults": 0}).status == 400
    assert (
        jira.request("GET", f"{API}/webhook", auth=app(jira), params={"maxResults": 0}).status
        == 400
    )


def test_default_page_sizes_follow_the_specs(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("A")
    assert agile(jira, "GET", "/board").body["maxResults"] == 50
    assert agile(jira, "GET", f"/board/{board}/sprint").body["maxResults"] == 50
    assert jira.request("GET", f"{API}/webhook", auth=app(jira)).body["maxResults"] == 100


def test_is_last_at_an_exact_multiple_of_the_page_size(jira: FakeJiraWorkflow) -> None:
    for n in range(4):
        jira.add_board(f"B{n}")

    def page(start: int, size: int) -> dict[str, Any]:
        r = agile(jira, "GET", "/board", params={"startAt": start, "maxResults": size})
        return dict(r.body)

    assert page(0, 2)["isLast"] is False
    assert page(2, 2)["isLast"] is True
    assert page(0, 4)["isLast"] is True
    assert page(0, 3)["isLast"] is False
    assert page(3, 3)["isLast"] is True
    assert page(8, 2)["values"] == []


# --- surviving mutants -------------------------------------------------------------------------


def test_negated_webhook_filters_match_the_complement(jira: FakeJiraWorkflow) -> None:
    issue = jira.add_issue(summary="a", project="SYN", status="In Progress")["key"]

    def fires(jql: str) -> bool:
        jira.clear_webhooks()
        assert "createdWebhookId" in results(register(jira, jqlFilter=jql))[0], jql
        return bool(jira.live_webhooks("jira:issue_updated", issue))

    assert fires("status != Done") is True
    assert fires("status != 'In Progress'") is False
    assert fires('status != "In Progress"') is False
    assert fires("project NOT IN (OTH)") is True
    assert fires("project NOT IN (OTH, SYN)") is False
    assert fires("status = 'In Progress' AND project != OTH") is True
    assert fires("status = 'In Progress' AND project != SYN") is False
    assert fires("project IN (SYN, OTH)") is True
    assert fires("project = OTH") is False


def test_not_equal_does_not_match_an_empty_field(jira: FakeJiraWorkflow) -> None:
    """JQL: ``!=`` and ``NOT IN`` do not match EMPTY (the JQL operators page)."""
    key = jira.add_issue(summary="a", assignee=None)["key"]
    for jql in ("assignee != 5bsynthetic0002", "assignee NOT IN (5bsynthetic0002)"):
        jira.clear_webhooks()
        results(register(jira, jqlFilter=jql))
        assert jira.live_webhooks("jira:issue_updated", key) == {}


@pytest.mark.parametrize(
    "jql",
    [
        "project IN SYN",
        "project NOT IN SYN",
        "project = (SYN, OTH)",
        "project != (SYN)",
        "project = ",
        "project IN ()",
    ],
)
def test_in_needs_a_list_and_equals_needs_one_value(jira: FakeJiraWorkflow, jql: str) -> None:
    assert "errors" in results(register(jira, jqlFilter=jql))[0]


def test_the_move_limit_is_exactly_fifty(jira: FakeJiraWorkflow) -> None:
    sprint = jira.add_sprint(jira.add_board("B"), "S", "active")
    keys = [jira.add_issue(summary=str(n))["key"] for n in range(51)]

    def move(ks: list[str]) -> Any:
        return agile(jira, "POST", f"/sprint/{sprint}/issue", json={"issues": ks})

    assert move(keys[:50]).status == 204
    assert move(keys).status == 400
    assert move(keys[:1]).status == 204


def test_the_reorder_fallback_runs_when_the_shuffle_keeps_the_order(
    jira: FakeJiraWorkflow,
) -> None:
    key = jira.add_issue(summary="a")["key"]
    hooks = FakeJiraWebhooks(jira)
    items = [hooks.admin_event(key), hooks.admin_event(key)]
    probe = list(items)
    random.Random(0).shuffle(probe)
    assert probe == items  # seed 0 leaves two items in place: the fallback must act
    assert hooks.unordered(items, seed=0) == items[::-1]
    three = [hooks.admin_event(key) for _ in range(3)]
    assert hooks.unordered(three, seed=0) != three


# --- nits --------------------------------------------------------------------------------------


def test_an_integer_transition_id_gets_a_specific_message(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    r = api(jira, "POST", f"/issue/{key}/transitions", json={"transition": {"id": 11}})
    assert r.status == 400
    assert "string" in r.body["errorMessages"][0]
    r = api(jira, "POST", f"/issue/{key}/transitions", json={})
    assert "string" not in r.body["errorMessages"][0]


def test_event_type_names(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    hooks = FakeJiraWebhooks(jira)

    def kind(event: str) -> str:
        return str(json.loads(hooks.admin_event(key, event).body)["issue_event_type_name"])

    assert kind("jira:issue_created") == "issue_created"
    assert kind("jira:issue_deleted") == "issue_deleted"
    assert kind("jira:issue_updated") == "issue_generic"


def test_sprint_list_order_is_closed_active_future(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("B")
    jira.add_sprint(board, "fut")
    jira.add_sprint(board, "act", "active")
    jira.add_sprint(board, "clo", "closed")
    jira.add_sprint(board, "clo2", "closed")
    got = agile(jira, "GET", f"/board/{board}/sprint").body["values"]
    assert [s["name"] for s in got] == ["clo", "clo2", "act", "fut"]


def test_failing_for_thirty_minutes_across_deliveries_limits_attempts(
    jira: FakeJiraWorkflow,
) -> None:
    key = jira.add_issue(summary="a")["key"]
    hooks = FakeJiraWebhooks(jira)
    assert len(hooks.deliver(lambda _r: 400, hooks.admin_event(key)).attempts) == 1
    assert hooks.degraded is False
    jira.now += 1900  # more than 30 minutes without a success
    assert len(hooks.deliver(lambda _r: 500, hooks.admin_event(key)).attempts) == 1
    assert hooks.degraded is True
    assert hooks.deliver(lambda _r: 200, hooks.admin_event(key)).delivered
    assert len(hooks.deliver(lambda _r: 500, hooks.admin_event(key)).attempts) == 6


def test_a_failure_shorter_than_thirty_minutes_keeps_full_retries(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    hooks = FakeJiraWebhooks(jira)
    hooks.deliver(lambda _r: 400, hooks.admin_event(key))
    jira.now += 1700
    assert hooks.degraded is False
    assert hooks.deliver(lambda _r: 500, hooks.admin_event(key)).delivered is False


def test_page_sizes_are_capped(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("A")
    assert agile(jira, "GET", "/board", params={"maxResults": 500}).body["maxResults"] == 50
    r = agile(jira, "GET", f"/board/{board}/sprint", params={"maxResults": 500})
    assert r.body["maxResults"] == 50
    hooks = jira.request("GET", f"{API}/webhook", auth=app(jira), params={"maxResults": 500})
    assert hooks.body["maxResults"] == 100


def test_moving_issues_refuses_query_parameters(jira: FakeJiraWorkflow) -> None:
    sprint = jira.add_sprint(jira.add_board("B"), "S", "active")
    key = jira.add_issue(summary="a")["key"]
    r = agile(jira, "POST", f"/sprint/{sprint}/issue", params={"x": 1}, json={"issues": [key]})
    assert r.status == 400
    assert agile(jira, "GET", f"/issue/{key}").body["fields"]["sprint"] is None
