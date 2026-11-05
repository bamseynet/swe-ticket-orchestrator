"""D6-09 review pass 2: each case answers one finding."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from fakes.jira.issues import BASIC, FakeJiraIssues
from fakes.jira.workflow import FakeJiraWebhooks, FakeJiraWorkflow

API, AGILE = "/rest/api/3", "/rest/agile/1.0"
ADF = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [
    {"type": "text", "text": "done"}]}]}  # fmt: skip
DATES = {"startDate": "2026-01-05T09:00:00.000Z", "endDate": "2026-01-19T09:00:00.000Z"}


@pytest.fixture
def jira() -> FakeJiraWorkflow:
    return FakeJiraWorkflow()


def agile(jira: FakeJiraWorkflow, method: str, path: str, **kw: Any) -> Any:
    return jira.request(method, AGILE + path, auth=BASIC, **kw)


def hook(jira: FakeJiraWorkflow, url: str) -> Any:
    body = {
        "url": url,
        "webhooks": [{"events": ["jira:issue_updated"], "jqlFilter": "project = SYN"}],
    }
    return jira.request("POST", f"{API}/webhook", auth=jira.new_bearer(), json=body)


def test_a_transition_comment_with_visibility_says_not_modelled(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    add = {"body": ADF, "visibility": {"type": "role", "value": "Administrators"}}
    r = jira.request(
        "POST",
        f"{API}/issue/{key}/transitions",
        auth=BASIC,
        json={"transition": {"id": "11"}, "update": {"comment": [{"add": add}]}},
    )
    assert r.status == 400
    assert "Not modelled by the fake Jira" in r.body["errors"]["comment"]
    bad = jira.request(
        "POST",
        f"{API}/issue/{key}/transitions",
        auth=BASIC,
        json={"transition": {"id": "11"}, "update": {"comment": [{"add": {"body": "x"}}]}},
    )
    assert bad.body["errors"]["comment"] == "Comment body is not valid!"


def test_sprint_issues_honour_the_fields_parameter(jira: FakeJiraWorkflow) -> None:
    sprint = jira.add_sprint(jira.add_board("B"), "S", "active")
    key = jira.add_issue(summary="a")["key"]
    agile(jira, "POST", f"/sprint/{sprint}/issue", json={"issues": [key]})
    r = agile(jira, "GET", f"/sprint/{sprint}/issue", params={"fields": "summary"})
    assert r.status == 200
    assert set(r.body["issues"][0]["fields"]) == {"summary"}
    full = agile(jira, "GET", f"/sprint/{sprint}/issue")
    assert {"summary", "sprint", "status"} <= set(full.body["issues"][0]["fields"])


@pytest.mark.parametrize("verb", ["PUT", "DELETE"])
def test_refresh_and_delete_refuse_extra_keys(jira: FakeJiraWorkflow, verb: str) -> None:
    wid = hook(jira, "https://a.example.test/h").body["webhookRegistrationResult"][0][
        "createdWebhookId"
    ]
    path = f"{API}/webhook" + ("/refresh" if verb == "PUT" else "")
    bad = jira.request(verb, path, auth=jira.new_bearer(), json={"webhookIds": [wid], "extra": 1})
    assert bad.status == 400
    assert jira.request("GET", f"{API}/webhook", auth=jira.new_bearer()).body["total"] == 1
    ok = jira.request(verb, path, auth=jira.new_bearer(), json={"webhookIds": [wid]})
    assert ok.status in (200, 202)


def test_the_failure_clock_is_per_recipient(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    hooks = FakeJiraWebhooks(jira)
    a, b = "https://a.example.test/h", "https://b.example.test/h"
    hooks.deliver(lambda _r: 400, hooks.admin_event(key), url=a)
    hooks.deliver(lambda _r: 400, hooks.admin_event(key), url=b)
    jira.now += 1900
    assert hooks.deliver(lambda _r: 200, hooks.admin_event(key), url=b).delivered  # b recovers
    assert hooks.degraded_for(b) is False
    assert hooks.degraded_for(a) is True  # a has still not succeeded
    assert len(hooks.deliver(lambda _r: 500, hooks.admin_event(key), url=a).attempts) == 1
    assert len(hooks.deliver(lambda _r: 500, hooks.admin_event(key), url=b).attempts) == 6


@pytest.mark.parametrize(("wait", "degraded"), [(1799, False), (1800, True)])
def test_the_thirty_minute_boundary(jira: FakeJiraWorkflow, wait: int, degraded: bool) -> None:
    key = jira.add_issue(summary="a")["key"]
    hooks = FakeJiraWebhooks(jira)
    hooks.deliver(lambda _r: 400, hooks.admin_event(key))
    jira.now += wait
    assert hooks.degraded is degraded
    attempts = hooks.deliver(lambda _r: 503, hooks.admin_event(key)).attempts
    assert len(attempts) == (1 if degraded else 6)


def test_float_and_integer_transition_ids_are_refused(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    for ident in (11, 11.0):
        r = jira.request(
            "POST", f"{API}/issue/{key}/transitions", auth=BASIC, json={"transition": {"id": ident}}
        )
        assert r.status == 400
        assert "string" in r.body["errorMessages"][0]


def test_a_closed_sprint_ignores_bad_dates(jira: FakeJiraWorkflow) -> None:
    sprint = jira.add_sprint(jira.add_board("B"), "S", "closed")
    before = agile(jira, "GET", f"/sprint/{sprint}").body
    r = agile(jira, "POST", f"/sprint/{sprint}", json={"startDate": "yesterday", "name": "N"})
    assert r.status == 200
    assert r.body["startDate"] == before["startDate"]
    assert r.body["name"] == "N"
    live = jira.add_sprint(jira.add_board("C"), "T")
    assert agile(jira, "POST", f"/sprint/{live}", json={"startDate": "yesterday"}).status == 400


def test_the_override_keeps_the_parents_add_issue_signature() -> None:
    ours = inspect.signature(FakeJiraWorkflow.add_issue)
    theirs = inspect.signature(FakeJiraIssues.add_issue)
    assert list(ours.parameters) == list(theirs.parameters)
    for name, param in theirs.parameters.items():
        assert ours.parameters[name].default == param.default, name
        assert ours.parameters[name].kind == param.kind, name
