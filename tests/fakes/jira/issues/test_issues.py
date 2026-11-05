"""D6-01: the fake Jira's issues, JQL search, comments, ADF, pagination, rate limits and errors.

Fixtures are synthetic. Each behaviour asserted here is documented, with its source URL, in
``server.py``; the live suite (D12) later proves it against the real service.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from fakes.jira.issues import (
    ACTIVE_CONTENT_ADF,
    BASIC,
    BEARER,
    SOURCES,
    FakeJiraIssues,
    RateShape,
    Response,
    adf,
    adf_to_text,
)

API = "/rest/api/3"


@pytest.fixture
def jira() -> FakeJiraIssues:
    return FakeJiraIssues()


def call(jira: FakeJiraIssues, method: str, path: str, **kw: Any) -> Response:
    kw.setdefault("auth", BASIC)
    return jira.request(method, API + path, **kw)


def search(jira: FakeJiraIssues, jql: str, **body: Any) -> Response:
    """A search asking for ``summary``, so that issues come back with their keys."""
    body.setdefault("fields", ["summary"])
    return call(jira, "POST", "/search/jql", json={"jql": jql, **body})


def keys(response: Response) -> list[str]:
    return [i["key"] for i in response.body["issues"]]


# --- documentation and synthetic fixtures -----------------------------------------------------


def test_every_operation_names_an_atlassian_source_url() -> None:
    assert SOURCES
    for op, url in SOURCES.items():
        assert url.startswith("https://developer.atlassian.com/cloud/jira/"), op


def test_the_module_documents_its_sources_and_departures() -> None:
    import fakes.jira.issues.server as server

    doc = server.__doc__ or ""
    assert "https://developer.atlassian.com/" in doc
    assert "Known departures" in doc


def test_fixtures_are_synthetic() -> None:
    import fakes.jira.issues.server as server

    assert server.HOST.endswith(".test")
    assert server.ACCOUNT_ID.startswith("5bsynthetic")
    assert "example" in server.EMAIL
    assert server.EMAIL.endswith(".test")


# --- authentication ----------------------------------------------------------------------------


def test_no_credentials_is_a_401(jira: FakeJiraIssues) -> None:
    assert jira.request("GET", API + "/issue/SYN-1").status == 401


def test_basic_and_bearer_credentials_are_both_accepted(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert call(jira, "GET", "/issue/SYN-1", auth=BASIC).status == 200
    assert call(jira, "GET", "/issue/SYN-1", auth=BEARER).status == 200


def test_wrong_basic_token_is_a_401(jira: FakeJiraIssues) -> None:
    bad = "Basic " + base64.b64encode(b"bot@example.test:wrong").decode()
    assert call(jira, "GET", "/issue/SYN-1", auth=bad).status == 401


def test_an_expired_bearer_token_is_a_401_until_a_new_one_is_issued(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.expire_bearer()
    assert call(jira, "GET", "/issue/SYN-1", auth=BEARER).status == 401
    assert call(jira, "GET", "/issue/SYN-1", auth=jira.new_bearer()).status == 200


def test_revoke_auth_makes_every_request_a_401(jira: FakeJiraIssues) -> None:
    jira.revoke_auth()
    assert call(jira, "GET", "/issue/SYN-1").status == 401
    jira.restore_auth()
    assert call(jira, "GET", "/issue/SYN-1").status == 404


# --- issues ------------------------------------------------------------------------------------


def test_create_then_get_an_issue(jira: FakeJiraIssues) -> None:
    created = call(
        jira,
        "POST",
        "/issue",
        json={
            "fields": {
                "project": {"key": "SYN"},
                "summary": "Fix the thing",
                "issuetype": {"name": "Task"},
                "description": adf("Body text"),
                "labels": ["agent-ready"],
            }
        },
    )
    assert created.status == 201
    assert created.body["key"] == "SYN-1"
    got = call(jira, "GET", "/issue/SYN-1").body
    assert got["fields"]["summary"] == "Fix the thing"
    assert got["fields"]["status"]["name"] == "To Do"
    assert got["fields"]["status"]["statusCategory"]["key"] == "new"
    assert adf_to_text(got["fields"]["description"]) == "Body text"
    assert got["fields"]["labels"] == ["agent-ready"]


def test_get_unknown_issue_is_a_404_with_jiras_message(jira: FakeJiraIssues) -> None:
    response = call(jira, "GET", "/issue/SYN-99")
    assert response.status == 404
    assert response.body == {
        "errorMessages": ["Issue does not exist or you do not have permission to see it."],
        "errors": {},
    }


def test_an_issue_in_a_denied_project_looks_like_a_missing_one(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="secret", project="HID")
    jira.deny_project("HID")
    assert call(jira, "GET", "/issue/HID-1").status == 404
    assert call(jira, "GET", "/issue/HID-1").body == call(jira, "GET", "/issue/SYN-99").body


def test_create_without_a_summary_is_a_400(jira: FakeJiraIssues) -> None:
    response = call(
        jira,
        "POST",
        "/issue",
        json={"fields": {"project": {"key": "SYN"}, "issuetype": {"name": "Task"}}},
    )
    assert response.status == 400
    assert response.body["errors"]["summary"] == "You must specify a summary of the issue."


def test_create_in_an_unknown_project_is_a_400(jira: FakeJiraIssues) -> None:
    response = call(
        jira,
        "POST",
        "/issue",
        json={
            "fields": {"project": {"key": "NOPE"}, "summary": "x", "issuetype": {"name": "Task"}}
        },
    )
    assert response.status == 400
    assert response.body["errors"]["project"] == "valid project is required"


def test_a_string_description_is_refused_because_v3_wants_adf(jira: FakeJiraIssues) -> None:
    response = call(
        jira,
        "POST",
        "/issue",
        json={
            "fields": {
                "project": {"key": "SYN"},
                "summary": "x",
                "issuetype": {"name": "Task"},
                "description": "plain",
            }
        },
    )
    assert response.status == 400
    assert response.body["errors"]["description"] == "Operation value must be an Atlassian Document"


def test_edit_changes_fields_and_returns_204_with_no_body(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="old", labels=["a"])
    response = call(
        jira,
        "PUT",
        "/issue/SYN-1",
        json={"fields": {"summary": "new"}, "update": {"labels": [{"add": "b"}, {"remove": "a"}]}},
    )
    assert response.status == 204
    assert response.body is None
    fields = call(jira, "GET", "/issue/SYN-1").body["fields"]
    assert fields["summary"] == "new"
    assert fields["labels"] == ["b"]
    assert fields["updated"] > fields["created"]


def test_get_issue_honours_the_fields_parameter(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", labels=["x"])
    got = call(jira, "GET", "/issue/SYN-1", params={"fields": "summary,labels"}).body
    assert set(got["fields"]) == {"summary", "labels"}


# --- JQL search and token pagination -----------------------------------------------------------


def seeded(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="one", labels=["agent-ready"], status="To Do")
    jira.add_issue(summary="two", labels=["agent-ready", "x"], status="In Progress")
    jira.add_issue(summary="three", status="Done", assignee=None)
    jira.add_issue(summary="other", project="OTH", labels=["agent-ready"])


def test_search_by_project_label_and_status(jira: FakeJiraIssues) -> None:
    seeded(jira)
    assert keys(search(jira, "project = SYN AND labels = agent-ready")) == ["SYN-1", "SYN-2"]
    assert keys(search(jira, 'project = SYN AND status = "in progress"')) == ["SYN-2"]
    assert keys(search(jira, "project = SYN AND status != Done")) == ["SYN-1", "SYN-2"]
    assert keys(search(jira, "project in (SYN, OTH) AND status = 'To Do'")) == ["SYN-1", "OTH-1"]


def test_search_or_and_parentheses(jira: FakeJiraIssues) -> None:
    seeded(jira)
    jql = "project = SYN AND (status = Done OR labels = x)"
    assert keys(search(jira, jql)) == ["SYN-2", "SYN-3"]


def test_search_empty_and_not_empty(jira: FakeJiraIssues) -> None:
    seeded(jira)
    assert keys(search(jira, "project = SYN AND labels is EMPTY")) == ["SYN-3"]
    assert keys(search(jira, "project = SYN AND labels is not EMPTY")) == ["SYN-1", "SYN-2"]


def test_search_text_contains_and_order_by(jira: FakeJiraIssues) -> None:
    seeded(jira)
    assert keys(search(jira, 'project = SYN AND summary ~ "TW"')) == ["SYN-2"]
    assert keys(search(jira, "project = SYN ORDER BY created DESC")) == ["SYN-3", "SYN-2", "SYN-1"]


def test_search_never_returns_a_denied_project(jira: FakeJiraIssues) -> None:
    seeded(jira)
    jira.deny_project("OTH")
    assert keys(search(jira, "labels = agent-ready")) == ["SYN-1", "SYN-2"]


def test_an_unbounded_query_is_refused(jira: FakeJiraIssues) -> None:
    assert search(jira, "").status == 400
    response = search(jira, "ORDER BY created")
    assert response.status == 400
    assert "Unbounded JQL queries are not allowed" in response.body["errorMessages"][0]


def test_an_unknown_field_and_a_syntax_error_are_400s(jira: FakeJiraIssues) -> None:
    unknown = search(jira, "bogus = 1")
    assert unknown.status == 400
    assert "Field 'bogus' does not exist or you do not have permission" in str(unknown.body)
    assert search(jira, "project = ").status == 400
    assert search(jira, "project = SYN AND").status == 400


def test_search_returns_only_ids_unless_fields_are_asked_for(jira: FakeJiraIssues) -> None:
    seeded(jira)
    bare = call(jira, "POST", "/search/jql", json={"jql": "project = SYN"}).body["issues"][0]
    assert bare == {"id": "10001"}  # spec: fields defaults to `id`, which returns only IDs
    rich = search(jira, "project = SYN", fields=["summary", "status"]).body["issues"][0]
    assert set(rich["fields"]) == {"summary", "status"}
    everything = search(jira, "project = SYN", fields=["*all"]).body["issues"][0]
    assert "labels" in everything["fields"]


def test_pagination_is_by_next_page_token_with_no_total(jira: FakeJiraIssues) -> None:
    for i in range(7):
        jira.add_issue(summary=f"s{i}")
    first = search(jira, "project = SYN", maxResults=3)
    assert keys(first) == ["SYN-1", "SYN-2", "SYN-3"]
    assert "total" not in first.body
    assert first.body["isLast"] is False
    second = search(jira, "project = SYN", maxResults=3, nextPageToken=first.body["nextPageToken"])
    assert keys(second) == ["SYN-4", "SYN-5", "SYN-6"]
    last = search(jira, "project = SYN", maxResults=3, nextPageToken=second.body["nextPageToken"])
    assert keys(last) == ["SYN-7"]
    assert last.body["isLast"] is True
    assert "nextPageToken" not in last.body


def test_a_result_that_fits_exactly_has_no_next_token(jira: FakeJiraIssues) -> None:
    for i in range(3):
        jira.add_issue(summary=f"s{i}")
    page = search(jira, "project = SYN", maxResults=3)
    assert page.body["isLast"] is True
    assert "nextPageToken" not in page.body


def test_default_page_size_is_50_and_the_cap_is_100(jira: FakeJiraIssues) -> None:
    for i in range(120):
        jira.add_issue(summary=f"s{i}")
    assert len(search(jira, "project = SYN").body["issues"]) == 50
    assert len(search(jira, "project = SYN", maxResults=500).body["issues"]) == 100


def test_a_garbled_or_expired_page_token_is_a_400(jira: FakeJiraIssues) -> None:
    for i in range(4):
        jira.add_issue(summary=f"s{i}")
    assert search(jira, "project = SYN", nextPageToken="garbage").status == 400
    token = search(jira, "project = SYN", maxResults=2).body["nextPageToken"]
    jira.expire_page_tokens()
    assert search(jira, "project = SYN", maxResults=2, nextPageToken=token).status == 400


def test_a_token_belongs_to_its_query(jira: FakeJiraIssues) -> None:
    for i in range(4):
        jira.add_issue(summary=f"s{i}")
    token = search(jira, "project = SYN", maxResults=2).body["nextPageToken"]
    other = search(jira, "project = SYN AND summary ~ s", maxResults=2, nextPageToken=token)
    assert other.status == 400


def test_an_issue_created_mid_paging_is_not_skipped_or_repeated(jira: FakeJiraIssues) -> None:
    for i in range(4):
        jira.add_issue(summary=f"s{i}")
    first = search(jira, "project = SYN ORDER BY created ASC", maxResults=2)
    jira.add_issue(summary="late")
    rest = search(
        jira,
        "project = SYN ORDER BY created ASC",
        maxResults=10,
        nextPageToken=first.body["nextPageToken"],
    )
    assert keys(first) + keys(rest) == ["SYN-1", "SYN-2", "SYN-3", "SYN-4", "SYN-5"]


# --- comments and ADF --------------------------------------------------------------------------


def test_add_and_list_comments_with_adf_bodies(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    added = call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf("hello")})
    assert added.status == 201
    assert added.body["author"]["accountId"].startswith("5bsynthetic")
    listing = call(jira, "GET", "/issue/SYN-1/comment").body
    assert listing["total"] == 1
    assert listing["startAt"] == 0
    assert listing["maxResults"] == 100  # spec: the comment default
    assert adf_to_text(listing["comments"][0]["body"]) == "hello"
    assert call(jira, "GET", f"/issue/SYN-1/comment/{added.body['id']}").status == 200


def test_a_plain_string_comment_body_is_refused(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    response = call(jira, "POST", "/issue/SYN-1/comment", json={"body": "plain"})
    assert response.status == 400


def test_invalid_adf_is_refused(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    for bad in (
        {"type": "doc", "version": 1, "content": []},
        {"type": "doc", "version": 1, "content": [{"type": "nope"}]},
        {"type": "doc", "version": 1, "content": [{"type": "text", "text": "top-level text"}]},
        {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": ""}]}],
        },
    ):
        assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": bad}).status == 400


def test_active_content_in_adf_is_stored_verbatim(jira: FakeJiraIssues) -> None:
    """The fake does not sanitise: converting ADF safely is the adapter's job (PLAN 10.4)."""
    jira.add_issue(summary="a")
    added = call(jira, "POST", "/issue/SYN-1/comment", json={"body": ACTIVE_CONTENT_ADF})
    assert added.status == 201
    assert added.body["body"] == ACTIVE_CONTENT_ADF


def test_comment_paging_is_offset_based_with_a_total(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    for i in range(5):
        call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf(f"c{i}")})
    page = call(jira, "GET", "/issue/SYN-1/comment", params={"startAt": 2, "maxResults": 2}).body
    assert page["total"] == 5
    assert [adf_to_text(c["body"]) for c in page["comments"]] == ["c2", "c3"]
    past = call(jira, "GET", "/issue/SYN-1/comment", params={"startAt": 9}).body
    assert past["comments"] == []
    assert past["total"] == 5
    newest = call(jira, "GET", "/issue/SYN-1/comment", params={"orderBy": "-created"}).body
    assert adf_to_text(newest["comments"][0]["body"]) == "c4"


def test_update_a_comment_and_a_missing_comment(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    cid = call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf("v1")}).body["id"]
    updated = call(jira, "PUT", f"/issue/SYN-1/comment/{cid}", json={"body": adf("v2")})
    assert updated.status == 200
    assert adf_to_text(updated.body["body"]) == "v2"
    assert updated.body["updated"] > updated.body["created"]
    assert call(jira, "PUT", "/issue/SYN-1/comment/999", json={"body": adf("x")}).status == 404
    assert call(jira, "POST", "/issue/SYN-9/comment", json={"body": adf("x")}).status == 404


def test_comments_on_a_denied_issue_are_a_404(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", project="HID")
    jira.deny_project("HID")
    assert call(jira, "GET", "/issue/HID-1/comment").status == 404


# --- rate limits and faults --------------------------------------------------------------------


def test_a_planted_429_carries_retry_after_and_a_reason(jira: FakeJiraIssues) -> None:
    jira.rate_limit_next(2, RateShape.PRIMARY_429)
    first = call(jira, "GET", "/issue/SYN-1")
    assert first.status == 429
    assert first.headers["retry-after"] == "30"
    assert first.headers["ratelimit-reason"] == "jira-burst-based"
    assert call(jira, "GET", "/issue/SYN-1").status == 429
    assert call(jira, "GET", "/issue/SYN-1").status == 404  # recovered


def test_only_the_shape_jira_uses_can_be_planted(jira: FakeJiraIssues) -> None:
    with pytest.raises(ValueError, match="429"):
        jira.rate_limit_next(1, RateShape.SECONDARY_403)


def test_the_budget_is_spent_then_refilled_when_the_window_passes(jira: FakeJiraIssues) -> None:
    jira.budget = 2
    assert call(jira, "GET", "/issue/SYN-1").status == 404
    assert call(jira, "GET", "/issue/SYN-1").status == 404
    limited = call(jira, "GET", "/issue/SYN-1")
    assert limited.status == 429
    assert int(limited.headers["retry-after"]) >= 1
    jira.now += 60
    assert call(jira, "GET", "/issue/SYN-1").status == 404


def test_rate_limiting_can_target_one_operation(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.rate_limit_next(1, RateShape.PRIMARY_429, op="search")
    assert call(jira, "GET", "/issue/SYN-1").status == 200
    assert search(jira, "project = SYN").status == 429


def test_fault_modes_5xx_timeout_and_401(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.fault_next("get_issue", "5xx")
    assert call(jira, "GET", "/issue/SYN-1").status == 503
    jira.fault_next("get_issue", "timeout")
    with pytest.raises(TimeoutError):
        call(jira, "GET", "/issue/SYN-1")
    jira.fault_next("get_issue", "401")
    assert call(jira, "GET", "/issue/SYN-1").status == 401
    assert call(jira, "GET", "/issue/SYN-1").status == 200


def test_a_fault_can_hit_one_page_of_a_search(jira: FakeJiraIssues) -> None:
    for i in range(4):
        jira.add_issue(summary=f"s{i}")
    jira.fault_next("search", "5xx", page=2)
    first = search(jira, "project = SYN", maxResults=2)
    assert first.status == 200
    broken = search(jira, "project = SYN", maxResults=2, nextPageToken=first.body["nextPageToken"])
    assert broken.status == 503


def test_a_lost_write_is_applied_but_the_caller_sees_a_timeout(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.fault_next("add_comment", "lose")
    with pytest.raises(TimeoutError):
        call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf("once")})
    assert call(jira, "GET", "/issue/SYN-1/comment").body["total"] == 1


def test_a_planted_plain_status(jira: FakeJiraIssues) -> None:
    jira.respond_next("get_issue", 403)
    assert call(jira, "GET", "/issue/SYN-1").status == 403


def test_counts_record_each_operation(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    call(jira, "GET", "/issue/SYN-1")
    call(jira, "GET", "/issue/SYN-1")
    search(jira, "project = SYN")
    assert jira.counts["get_issue"] == 2
    assert jira.counts["search"] == 1


def test_an_unknown_route_is_a_404(jira: FakeJiraIssues) -> None:
    assert call(jira, "GET", "/nothing").status == 404
