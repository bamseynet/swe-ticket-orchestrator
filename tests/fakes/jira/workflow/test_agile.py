"""D6-09: boards and sprints (Jira Software Cloud REST, ``/rest/agile/1.0``). Synthetic fixtures."""

from __future__ import annotations

from typing import Any

import pytest

from fakes.jira.issues import BASIC
from fakes.jira.workflow import FakeJiraWorkflow

AGILE = "/rest/agile/1.0"
DATES = {"startDate": "2026-01-05T09:00:00.000Z", "endDate": "2026-01-19T09:00:00.000Z"}


@pytest.fixture
def jira() -> FakeJiraWorkflow:
    return FakeJiraWorkflow()


def get(jira: FakeJiraWorkflow, path: str, **params: Any) -> Any:
    return jira.request("GET", AGILE + path, auth=BASIC, params=params)


def send(jira: FakeJiraWorkflow, method: str, path: str, body: Any) -> Any:
    return jira.request(method, AGILE + path, auth=BASIC, json=body)


def test_boards_list_filters_and_pages(jira: FakeJiraWorkflow) -> None:
    jira.add_board("Scrum", "scrum", "SYN")
    jira.add_board("Flow", "kanban", "SYN")
    jira.add_board("Other", "scrum", "OTH")
    r = get(jira, "/board")
    assert r.status == 200
    assert r.body["total"] == 3
    assert r.body["isLast"] is True
    assert {"id", "self", "name", "type"} <= set(r.body["values"][0])
    assert [b["name"] for b in get(jira, "/board", type="kanban").body["values"]] == ["Flow"]
    assert [b["name"] for b in get(jira, "/board", projectKeyOrId="OTH").body["values"]] == [
        "Other"
    ]
    page = get(jira, "/board", maxResults=2).body
    assert len(page["values"]) == 2
    assert page["isLast"] is False
    rest = get(jira, "/board", startAt=2, maxResults=2).body
    assert len(rest["values"]) == 1
    assert rest["isLast"] is True
    assert get(jira, "/board", type="wrong").status == 400


def test_board_lookup_and_missing(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Scrum", "scrum", "SYN")
    assert get(jira, f"/board/{board}").body["name"] == "Scrum"
    assert get(jira, "/board/999").status == 404
    assert get(jira, "/board/abc").status == 404


def test_sprint_states_and_the_active_filter(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Scrum", "scrum", "SYN")
    s1 = jira.add_sprint(board, "S1", "closed")
    s2 = jira.add_sprint(board, "S2", "active")
    s3 = jira.add_sprint(board, "S3", "future")
    every = get(jira, f"/board/{board}/sprint").body["values"]
    assert [s["id"] for s in every] == [s1, s2, s3]
    active = get(jira, f"/board/{board}/sprint", state="active").body["values"]
    assert [(s["name"], s["state"]) for s in active] == [("S2", "active")]
    both = get(jira, f"/board/{board}/sprint", state="active,future").body["values"]
    assert [s["id"] for s in both] == [s2, s3]
    assert {"startDate", "endDate", "originBoardId"} <= set(active[0])
    assert get(jira, f"/board/{board}/sprint", state="bogus").status == 400


def test_no_active_sprint_is_an_empty_list(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Scrum", "scrum", "SYN")
    jira.add_sprint(board, "S1", "future")
    r = get(jira, f"/board/{board}/sprint", state="active")
    assert r.status == 200
    assert r.body["values"] == []
    assert r.body["isLast"] is True


def test_kanban_board_does_not_support_sprints(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Flow", "kanban", "SYN")
    r = get(jira, f"/board/{board}/sprint")
    assert r.status == 400
    assert r.body["errorMessages"]


def test_team_managed_board_depends_on_the_sprint_feature(jira: FakeJiraWorkflow) -> None:
    on = jira.add_board("TM", "simple", "SYN", sprints=True)
    off = jira.add_board("TM off", "simple", "OTH", sprints=False)
    assert get(jira, f"/board/{on}/sprint").status == 200
    assert get(jira, f"/board/{off}/sprint").status == 400


def test_sprint_lifecycle_through_the_api(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Scrum", "scrum", "SYN")
    s1, s2 = jira.add_sprint(board, "S1", "future"), jira.add_sprint(board, "S2", "future")
    assert send(jira, "POST", f"/sprint/{s1}", {"state": "active", **DATES}).status == 200
    assert get(jira, f"/sprint/{s1}").body["state"] == "active"
    # one active sprint at a time unless parallel sprints are on
    assert send(jira, "POST", f"/sprint/{s2}", {"state": "active", **DATES}).status == 400
    assert send(jira, "POST", f"/sprint/{s1}", {"state": "closed"}).status == 200
    assert send(jira, "POST", f"/sprint/{s2}", {"state": "active", **DATES}).status == 200
    assert send(jira, "POST", f"/sprint/{s1}", {"state": "future"}).status == 400  # no way back
    assert send(jira, "POST", f"/sprint/{s1}", {"state": "bogus"}).status == 400
    assert get(jira, "/sprint/999").status == 404


def test_parallel_sprints_allow_two_active(jira: FakeJiraWorkflow) -> None:
    jira = FakeJiraWorkflow(parallel_sprints=True)
    board = jira.add_board("Scrum", "scrum", "SYN")
    a, b = jira.add_sprint(board, "A", "future"), jira.add_sprint(board, "B", "future")
    assert send(jira, "POST", f"/sprint/{a}", {"state": "active", **DATES}).status == 200
    assert send(jira, "POST", f"/sprint/{b}", {"state": "active", **DATES}).status == 200


def test_moving_issues_into_a_sprint_moves_eligibility(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Scrum", "scrum", "SYN")
    old = jira.add_sprint(board, "Old", "active")
    new = jira.add_sprint(board, "New", "future")
    key = jira.add_issue(summary="a")["key"]
    assert send(jira, "POST", f"/sprint/{old}/issue", {"issues": [key]}).status == 204
    issue = get(jira, f"/issue/{key}").body
    assert issue["fields"]["sprint"]["id"] == old
    assert issue["fields"]["closedSprints"] == []
    assert send(jira, "POST", f"/sprint/{new}/issue", {"issues": [key]}).status == 204
    assert get(jira, f"/issue/{key}").body["fields"]["sprint"]["id"] == new  # moved, not copied
    assert get(jira, f"/sprint/{old}/issue").body["issues"] == []
    assert [i["key"] for i in get(jira, f"/sprint/{new}/issue").body["issues"]] == [key]


def test_closing_a_sprint_records_it_on_the_issue(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Scrum", "scrum", "SYN")
    s = jira.add_sprint(board, "S", "active")
    key = jira.add_issue(summary="a")["key"]
    send(jira, "POST", f"/sprint/{s}/issue", {"issues": [key]})
    send(jira, "POST", f"/sprint/{s}", {"state": "closed"})
    fields = get(jira, f"/issue/{key}").body["fields"]
    assert fields["sprint"] is None
    assert [c["id"] for c in fields["closedSprints"]] == [s]


def test_sprint_move_limits(jira: FakeJiraWorkflow) -> None:
    board = jira.add_board("Scrum", "scrum", "SYN")
    open_, shut = jira.add_sprint(board, "O", "active"), jira.add_sprint(board, "C", "closed")
    key = jira.add_issue(summary="a")["key"]
    assert send(jira, "POST", f"/sprint/{shut}/issue", {"issues": [key]}).status == 400
    assert send(jira, "POST", f"/sprint/{open_}/issue", {"issues": ["SYN-404"]}).status == 400
    assert send(jira, "POST", f"/sprint/{open_}/issue", {"issues": []}).status == 400
    many = [f"SYN-{n}" for n in range(1, 52)]
    assert send(jira, "POST", f"/sprint/{open_}/issue", {"issues": many}).status == 400  # max 50
    assert send(jira, "POST", "/sprint/999/issue", {"issues": [key]}).status == 404


def test_agile_auth_limits_and_unknown_paths(jira: FakeJiraWorkflow) -> None:
    assert jira.request("GET", AGILE + "/board", auth=None).status == 401
    assert jira.request("GET", AGILE + "/nope", auth=BASIC).status == 404
    jira.respond_next("list_boards", 503)
    assert get(jira, "/board").status == 503
    assert get(jira, "/board").status == 200
