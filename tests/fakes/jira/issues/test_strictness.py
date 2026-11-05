"""D6-01 pass 1: the fake is as strict as Jira where adapters will be tested against it.

Each test names the spec schema or Atlassian page it follows (the v3 OpenAPI document, cited
as "spec" in ``server.py``). Fixtures are synthetic.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from fakes.jira.issues import BASIC, FakeJiraIssues, RateShape, Response, adf, adf_to_text
from fakes.jira.issues.server import ACCOUNT_ID

API = "/rest/api/3"


@pytest.fixture
def jira() -> FakeJiraIssues:
    return FakeJiraIssues()


def call(jira: FakeJiraIssues, method: str, path: str, **kw: Any) -> Response:
    kw.setdefault("auth", BASIC)
    return jira.request(method, API + path, **kw)


def search(jira: FakeJiraIssues, jql: str, **body: Any) -> Response:
    body.setdefault("fields", ["summary"])
    return call(jira, "POST", "/search/jql", json={"jql": jql, **body})


def keys(response: Response) -> list[str]:
    assert response.status == 200, response.body
    return [i["key"] for i in response.body["issues"]]


def create(jira: FakeJiraIssues, **fields: Any) -> Response:
    base = {"project": {"key": "SYN"}, "summary": "x", "issuetype": {"name": "Task"}}
    return call(jira, "POST", "/issue", json={"fields": {**base, **fields}})


# --- 1: create and edit validate every field ---------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "name"),
    [
        ({"customfield_99999": "ac"}, "customfield_99999"),
        ({"issuetype": {"name": "NoSuchType"}}, "issuetype"),
        ({"priority": {"name": "Bogus"}}, "priority"),
        ({"labels": ["has space"]}, "labels"),
        ({"assignee": {"accountId": "nobody"}}, "assignee"),
        ({"summary": "   "}, "summary"),
        ({"summary": "x" * 256}, "summary"),
    ],
)
def test_create_refuses_each_invalid_field_with_the_errors_map(
    jira: FakeJiraIssues, fields: dict[str, Any], name: str
) -> None:
    response = create(jira, **fields)
    assert response.status == 400
    assert name in response.body["errors"]
    assert not jira._issues


def test_create_reports_every_bad_field_at_once(jira: FakeJiraIssues) -> None:
    response = create(jira, priority={"name": "Bogus"}, labels=["a b"], customfield_1="x")
    assert set(response.body["errors"]) == {"priority", "labels", "customfield_1"}


@pytest.mark.parametrize(
    "fields",
    [
        {"customfield_12345": "x"},
        {"summary": ""},
        {"labels": ["has space"]},
        {"priority": {"name": "Bogus"}},
        {"assignee": {"accountId": "nobody"}},
        {"issuetype": {"name": "Bug"}},  # create-only
    ],
)
def test_edit_refuses_the_same_and_changes_nothing(
    jira: FakeJiraIssues, fields: dict[str, Any]
) -> None:
    jira.add_issue(summary="keep", labels=["a"])
    before = json.dumps(jira._issues["SYN-1"], sort_keys=True)
    response = call(jira, "PUT", "/issue/SYN-1", json={"fields": {"summary": "new", **fields}})
    assert response.status == 400
    assert json.dumps(jira._issues["SYN-1"], sort_keys=True) == before


def test_a_valid_edit_with_one_invalid_field_applies_nothing(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="keep")
    call(jira, "PUT", "/issue/SYN-1", json={"fields": {"summary": "new", "labels": ["a b"]}})
    assert jira._issues["SYN-1"]["fields"]["summary"] == "keep"


# --- 2: issueIdOrKey takes both; project and issuetype by id ------------------------------------


def test_an_issue_is_reachable_by_numeric_id_and_by_its_own_self_url(jira: FakeJiraIssues) -> None:
    issue = jira.add_issue(summary="a")
    by_id = call(jira, "GET", "/issue/" + issue["id"])
    assert by_id.status == 200
    assert by_id.body["key"] == "SYN-1"
    own_url = issue["self"].removeprefix("https://synthetic-site.atlassian.test" + API)
    assert call(jira, "GET", own_url).status == 200
    assert call(jira, "PUT", own_url, json={"fields": {"summary": "b"}}).status == 204
    assert call(jira, "POST", own_url + "/comment", json={"body": adf("hi")}).status == 201
    assert call(jira, "GET", own_url + "/comment").body["total"] == 1


def test_create_takes_project_and_issuetype_by_id(jira: FakeJiraIssues) -> None:
    response = call(
        jira,
        "POST",
        "/issue",
        json={"fields": {"project": {"id": "10000"}, "summary": "x", "issuetype": {"id": "10002"}}},
    )
    assert response.status == 201
    fields = call(jira, "GET", "/issue/" + response.body["id"]).body["fields"]
    assert fields["issuetype"]["name"] == "Bug"
    assert fields["project"]["key"] == "SYN"


def test_a_numeric_id_of_a_denied_project_is_a_404(jira: FakeJiraIssues) -> None:
    issue = jira.add_issue(summary="a", project="OTH")
    jira.deny_project("OTH")
    assert call(jira, "GET", "/issue/" + issue["id"]).status == 404


def test_priority_by_id_edits_and_a_bad_id_is_a_400_not_a_crash(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert (
        call(jira, "PUT", "/issue/SYN-1", json={"fields": {"priority": {"id": "1"}}}).status == 204
    )
    assert jira._issues["SYN-1"]["fields"]["priority"]["name"] == "Highest"
    bad = call(jira, "PUT", "/issue/SYN-1", json={"fields": {"priority": {"id": "99"}}})
    assert bad.status == 400


# --- edit: update operations --------------------------------------------------------------------


def test_edit_update_set_and_label_operations(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", labels=["x", "y"])
    update = {"summary": [{"set": "b"}], "labels": [{"remove": "x"}, {"add": "z"}, {"add": "z"}]}
    assert call(jira, "PUT", "/issue/SYN-1", json={"update": update}).status == 204
    fields = jira._issues["SYN-1"]["fields"]
    assert fields["summary"] == "b"
    assert fields["labels"] == ["y", "z"]
    call(jira, "PUT", "/issue/SYN-1", json={"update": {"labels": [{"set": ["only"]}]}})
    assert jira._issues["SYN-1"]["fields"]["labels"] == ["only"]


def test_edit_refuses_operations_it_does_not_model(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert (
        call(jira, "PUT", "/issue/SYN-1", json={"update": {"labels": [{"edit": "x"}]}}).status
        == 400
    )
    assert (
        call(jira, "PUT", "/issue/SYN-1", json={"update": {"summary": [{"add": "x"}]}}).status
        == 400
    )
    assert call(jira, "PUT", "/issue/SYN-1", json={"update": {"nope": [{"set": 1}]}}).status == 400
    moved = call(jira, "PUT", "/issue/SYN-1", json={"transition": {"id": "11"}})
    assert moved.status == 400
    assert moved.body["errorMessages"] == [
        "Not modelled by the fake Jira: 'transition' and 'properties' on edit."
    ]
    made = call(jira, "POST", "/issue", json={"fields": {}, "properties": [{"key": "k"}]})
    assert "Not modelled" in made.body["errorMessages"][0]


def test_edit_refuses_a_field_given_in_both_fields_and_update(jira: FakeJiraIssues) -> None:
    """Spec, IssueUpdateDetails: fields in ``fields`` cannot be included in ``update``."""
    jira.add_issue(summary="a")
    body = {"fields": {"summary": "b"}, "update": {"summary": [{"set": "c"}]}}
    response = call(jira, "PUT", "/issue/SYN-1", json=body)
    assert response.status == 400
    assert "summary" in response.body["errors"]
    assert jira._issues["SYN-1"]["fields"]["summary"] == "a"


# --- 3, 4: JQL ---------------------------------------------------------------------------------


def test_not_equals_and_not_in_do_not_match_an_empty_field(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="unassigned", assignee=None, labels=[])
    jira.add_issue(summary="mine")
    jira.add_issue(summary="theirs", assignee="5bsynthetic0002")
    assert keys(search(jira, f"project = SYN AND assignee != {ACCOUNT_ID}")) == ["SYN-3"]
    assert keys(search(jira, f"project = SYN AND assignee not in ({ACCOUNT_ID})")) == ["SYN-3"]
    assert keys(search(jira, "project = SYN AND labels != x")) == []  # nobody has any labels


def test_label_not_equals_matches_issues_that_have_other_labels_only(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", labels=["x"])
    jira.add_issue(summary="b", labels=["y"])
    jira.add_issue(summary="c", labels=["x", "y"])
    assert keys(search(jira, "project = SYN AND labels != x")) == ["SYN-2"]
    assert keys(search(jira, "project = SYN AND labels not in (x)")) == ["SYN-2"]


def test_dates_compare_as_dates_in_both_formats(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="early")  # 2026-01-01 00:00:00
    jira.now += 3600
    jira.add_issue(summary="later")  # 2026-01-01 01:00:01
    assert keys(search(jira, "project = SYN AND created >= 2026/01/01")) == ["SYN-1", "SYN-2"]
    assert keys(search(jira, "project = SYN AND created > 2026-01-01")) == ["SYN-2"]
    assert keys(search(jira, 'project = SYN AND created >= "2026-01-01 01:00"')) == ["SYN-2"]
    assert keys(search(jira, 'project = SYN AND created < "2026/01/01 01:00"')) == ["SYN-1"]
    assert keys(search(jira, 'project = SYN AND created <= "2026-01-01 00:00"')) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND updated >= 2026/01/02")) == []
    assert keys(search(jira, "project = SYN AND created < 2025-12-31")) == []


def test_a_date_is_not_compared_as_text(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    # as text "2026/01/01" < "2026-01-01T..." and "2026-1-1" would sort wrongly
    assert keys(search(jira, 'project = SYN AND created >= "2025-12-31 23:59"')) == ["SYN-1"]
    assert keys(search(jira, 'project = SYN AND created <= "2026/01/01 00:00"')) == ["SYN-1"]


@pytest.mark.parametrize(
    "clause",
    [
        "updated >= -1d",
        "created >= startOfDay()",
        "assignee = currentUser()",
        "created = 2026-01-01",
        "created in (2026-01-01)",
        "labels ~ x",
        "summary = a",
        "status > a",
        "labels > a",
        "created >= nonsense",
        "NOT labels = x",
        "status = NoSuchStatus",
        "priority = Bogus",
        "project = NOPE",
        "key >= banana",
    ],
)
def test_unmodelled_or_unsupported_jql_is_a_400_never_a_wrong_answer(
    jira: FakeJiraIssues, clause: str
) -> None:
    jira.add_issue(summary="a")
    response = search(jira, f"project = SYN AND {clause}")
    assert response.status == 400
    assert response.body["errorMessages"]


def test_the_text_of_the_refusal_says_whether_it_is_unmodelled(jira: FakeJiraIssues) -> None:
    relative = search(jira, "project = SYN AND updated >= -1d")
    assert "Not modelled by the fake Jira" in relative.body["errorMessages"][0]
    wrong = search(jira, "project = SYN AND labels ~ x")
    assert wrong.body["errorMessages"] == [
        "The operator '~' is not supported by the 'labels' field."
    ]


def test_key_compares_and_sorts_by_issue_number(jira: FakeJiraIssues) -> None:
    for n in range(10):
        jira.add_issue(summary=f"s{n}")
    assert keys(search(jira, "project = SYN AND key >= SYN-9")) == ["SYN-9", "SYN-10"]
    assert keys(search(jira, "project = SYN AND key < SYN-3")) == ["SYN-1", "SYN-2"]
    assert keys(search(jira, "project = SYN ORDER BY key DESC", maxResults=3)) == [
        "SYN-10",
        "SYN-9",
        "SYN-8",
    ]
    assert keys(search(jira, "key in (SYN-2, SYN-10)")) == ["SYN-2", "SYN-10"]


def test_project_can_be_given_by_id(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b", project="OTH")
    assert keys(search(jira, "project = 10000")) == ["SYN-1"]
    assert keys(search(jira, "project in (10000, oth)")) == ["SYN-1", "OTH-1"]


def test_order_by_a_value_named_order_and_a_quoted_order_by(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="x", labels=["order"])
    jira.add_issue(summary="order by created", labels=["z"])
    assert keys(search(jira, "labels = order ORDER BY created DESC")) == ["SYN-1"]
    assert keys(search(jira, 'summary ~ "order by created" ORDER BY created')) == ["SYN-2"]
    assert keys(search(jira, "summary ~ 'it\\'s' OR labels = z")) == ["SYN-2"]


@pytest.mark.parametrize(
    "jql",
    [
        "project = SYN ORDER BY created DESC,",
        "project = SYN ORDER BY",
        "project = SYN ORDER BY labels",
        "project = SYN ORDER BY created created",
        "project = SYN ORDER created",
        "project = SYN ORDER foo created",
        "project = SYN ORDER",
        "project = SYN AND",
        "project = ",
        "(project = SYN",
    ],
)
def test_malformed_order_by_and_syntax_are_400s(jira: FakeJiraIssues, jql: str) -> None:
    assert search(jira, jql).status == 400


def test_order_by_priority_and_two_keys(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", priority="Low")
    jira.add_issue(summary="b", priority="Highest")
    jira.add_issue(summary="c", priority="Low")
    assert keys(search(jira, "project = SYN ORDER BY priority ASC, created DESC")) == [
        "SYN-3",
        "SYN-1",
        "SYN-2",
    ]


# --- 5: paging continues after the position, not the issue --------------------------------------


def test_paging_continues_after_the_last_position_when_that_issue_stops_matching(
    jira: FakeJiraIssues,
) -> None:
    for n in range(6):
        jira.add_issue(summary=f"s{n}", labels=["ready"])
    first = search(jira, "labels = ready", maxResults=2)
    assert keys(first) == ["SYN-1", "SYN-2"]
    call(jira, "PUT", "/issue/SYN-2", json={"update": {"labels": [{"remove": "ready"}]}})
    second = search(jira, "labels = ready", maxResults=2, nextPageToken=first.body["nextPageToken"])
    assert keys(second) == ["SYN-3", "SYN-4"]


def test_paging_in_descending_order_holds_across_a_change(jira: FakeJiraIssues) -> None:
    for n in range(5):
        jira.add_issue(summary=f"s{n}")
    jql = "project = SYN ORDER BY key DESC"
    first = search(jira, jql, maxResults=2)
    jira.add_issue(summary="newest")  # sorts before everything already returned
    rest = search(jira, jql, maxResults=10, nextPageToken=first.body["nextPageToken"])
    assert keys(first) + keys(rest) == ["SYN-5", "SYN-4", "SYN-3", "SYN-2", "SYN-1"]


def test_a_page_token_expires_after_seven_days(jira: FakeJiraIssues) -> None:
    """Spec, SearchAndReconcileResults: the token "will expire in 7 days"."""
    for n in range(3):
        jira.add_issue(summary=f"s{n}")
    token = search(jira, "project = SYN", maxResults=1).body["nextPageToken"]
    jira.now += 6 * 24 * 3600
    assert search(jira, "project = SYN", maxResults=1, nextPageToken=token).status == 200
    jira.now += 2 * 24 * 3600
    assert search(jira, "project = SYN", maxResults=1, nextPageToken=token).status == 400


# --- 7: the search body is closed ---------------------------------------------------------------


@pytest.mark.parametrize("extra", [{"startAt": 2}, {"total": True}, {"orderBy": "key"}])
def test_unknown_search_body_keys_are_a_400(jira: FakeJiraIssues, extra: dict[str, Any]) -> None:
    """Spec: SearchAndReconcileRequestBean has additionalProperties false."""
    jira.add_issue(summary="a")
    assert search(jira, "project = SYN", **extra).status == 400


@pytest.mark.parametrize(
    "extra",
    [{"expand": "names"}, {"properties": ["p"]}, {"fieldsByKeys": True}, {"reconcileIssues": [1]}],
)
def test_search_keys_the_spec_has_but_the_fake_does_not_model_are_refused(
    jira: FakeJiraIssues, extra: dict[str, Any]
) -> None:
    response = search(jira, "project = SYN", **extra)
    assert response.status == 400
    assert "Not modelled" in response.body["errorMessages"][0]


@pytest.mark.parametrize("size", [0, -1, "x", True, 1.5])
def test_search_max_results_must_be_a_positive_integer(jira: FakeJiraIssues, size: Any) -> None:
    jira.add_issue(summary="a")
    assert search(jira, "project = SYN", maxResults=size).status == 400
    assert search(jira, "project = SYN", maxResults=1).status == 200


def test_search_body_types_are_checked(jira: FakeJiraIssues) -> None:
    assert search(jira, 5).status == 400  # type: ignore[arg-type]
    assert search(jira, "project = SYN", fields=5).status == 400
    assert search(jira, "project = SYN", nextPageToken=5).status == 400


def test_search_fields_accepts_a_comma_string_and_exclusions(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", labels=["x"])
    csv = search(jira, "project = SYN", fields="summary,labels").body["issues"][0]
    assert set(csv["fields"]) == {"summary", "labels"}
    rest = search(jira, "project = SYN", fields=["*all", "-description"]).body["issues"][0]
    assert "description" not in rest["fields"]
    assert "summary" in rest["fields"]


# --- 8: comments --------------------------------------------------------------------------------


def test_comment_page_defaults_to_100_and_order_by_follows_the_spec_enum(
    jira: FakeJiraIssues,
) -> None:
    jira.add_issue(summary="a")
    for n in range(120):
        call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf(f"c{n}")})
    page = call(jira, "GET", "/issue/SYN-1/comment").body
    assert page["maxResults"] == 100
    assert len(page["comments"]) == 100
    for ok in ("created", "-created", "+created"):
        assert call(jira, "GET", "/issue/SYN-1/comment", params={"orderBy": ok}).status == 200
    assert call(jira, "GET", "/issue/SYN-1/comment", params={"orderBy": "bogus"}).status == 400


@pytest.mark.parametrize("params", [{"startAt": -1}, {"startAt": "x"}, {"maxResults": 0}])
def test_comment_paging_parameters_are_checked(
    jira: FakeJiraIssues, params: dict[str, Any]
) -> None:
    jira.add_issue(summary="a")
    assert call(jira, "GET", "/issue/SYN-1/comment", params=params).status == 400


def test_comment_visibility_and_properties_are_refused_as_not_modelled(
    jira: FakeJiraIssues,
) -> None:
    jira.add_issue(summary="a")
    body = {"body": adf("x"), "visibility": {"type": "role", "value": "Administrators"}}
    assert call(jira, "POST", "/issue/SYN-1/comment", json=body).status == 400


# --- 9: forged tokens are 400s, after authentication --------------------------------------------


def _forged(jira: FakeJiraIssues, jql: str = "project = SYN", **override: Any) -> str:
    """A token that passes the query and epoch checks, so only the overridden part is wrong."""
    digest = hashlib.sha256(jql.encode()).hexdigest()[:12]
    body = {"q": digest, "e": 0, "p": 1, "t": jira.now, "k": [10001], **override}
    return base64.urlsafe_b64encode(json.dumps(body).encode()).decode()


@pytest.mark.parametrize(
    "override",
    [
        {"p": "z"},
        {"p": 0},
        {"p": True},
        {"e": "0"},
        {"k": "no"},
        {"k": []},
        {"k": ["text"]},
        {"t": "now"},
    ],
)
def test_a_forged_page_token_is_a_400_and_never_an_exception(
    jira: FakeJiraIssues, override: dict[str, Any]
) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b")
    token = _forged(jira, **override)
    assert search(jira, "project = SYN", nextPageToken=token).status == 400
    response = jira.request(
        "POST", API + "/search/jql", json={"jql": "project = SYN", "nextPageToken": token}
    )
    assert response.status == 401  # authentication comes first


def test_a_well_formed_forged_token_is_the_control_for_the_cases_above(
    jira: FakeJiraIssues,
) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b")
    assert keys(search(jira, "project = SYN", nextPageToken=_forged(jira))) == ["SYN-2"]


@pytest.mark.parametrize(
    "token",
    [
        base64.urlsafe_b64encode(b"[1, 2]").decode(),
        base64.urlsafe_b64encode(b"\xff\xfe").decode(),
        "!!!",
    ],
)
def test_garbage_tokens_are_a_400(jira: FakeJiraIssues, token: str) -> None:
    assert search(jira, "project = SYN", nextPageToken=token).status == 400


# --- 10: a comment is activity on the issue ------------------------------------------------------


def test_adding_or_updating_a_comment_bumps_the_issues_updated(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    before = jira._issues["SYN-1"]["fields"]["updated"]
    jira.now += 100
    cid = call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf("hi")}).body["id"]
    added = jira._issues["SYN-1"]["fields"]["updated"]
    assert added > before
    assert keys(search(jira, 'project = SYN AND updated > "2026-01-01 00:01"')) == ["SYN-1"]
    jira.now += 100
    call(jira, "PUT", f"/issue/SYN-1/comment/{cid}", json={"body": adf("hi2")})
    assert jira._issues["SYN-1"]["fields"]["updated"] > added


# --- 11: behaviours that were left unasserted ----------------------------------------------------


def test_the_retry_after_of_a_spent_budget_is_what_remains_of_the_window(
    jira: FakeJiraIssues,
) -> None:
    jira.budget = 1
    call(jira, "GET", "/issue/SYN-1")
    assert call(jira, "GET", "/issue/SYN-1").headers["Retry-After"] == "60"
    jira.now += 25
    assert call(jira, "GET", "/issue/SYN-1").headers["Retry-After"] == "35"


def test_a_planted_429_says_retry_after_30(jira: FakeJiraIssues) -> None:
    jira.rate_limit_next(1, RateShape.PRIMARY_429)
    assert call(jira, "GET", "/issue/SYN-1").headers["Retry-After"] == "30"


def test_headers_are_found_whatever_the_case(jira: FakeJiraIssues) -> None:
    jira.rate_limit_next(1, RateShape.PRIMARY_429)
    headers = call(jira, "GET", "/issue/SYN-1").headers
    assert headers["Retry-After"] == headers["retry-after"] == headers["RETRY-AFTER"]
    assert "retry-after" in headers
    assert "Retry-After" in list(headers)
    assert headers.get("X-Nothing") is None
    assert len(headers) == 2


def test_an_unknown_adf_mark_on_a_text_node_is_refused(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    text = {"type": "text", "text": "x", "marks": [{"type": "sparkle"}]}
    doc = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [text]}]}
    assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": doc}).status == 400
    text["marks"] = [{"type": "strong"}]
    assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": doc}).status == 201
    text["marks"] = "strong"
    assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": doc}).status == 400


def test_a_lost_response_does_not_leak_into_the_next_request(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.fault_next("add_comment", "lose")
    assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": "plain"}).status == 400
    assert call(jira, "GET", "/issue/SYN-1").status == 200
    assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf("ok")}).status == 201


# --- 12: ADF ------------------------------------------------------------------------------------


def _node(kind: str, *content: Any) -> dict[str, Any]:
    return {"type": kind, "content": list(content)}


def _text(value: str) -> dict[str, Any]:
    return {"type": "text", "text": value}


def test_adf_to_text_separates_list_items_and_quoted_paragraphs() -> None:
    items = _node(
        "bulletList",
        _node("listItem", _node("paragraph", _text("one"))),
        _node("listItem", _node("paragraph", _text("two"))),
    )
    quote = _node("blockquote", _node("paragraph", _text("a")), _node("paragraph", _text("b")))
    doc = {"type": "doc", "version": 1, "content": [items, quote]}
    assert adf_to_text(doc) == "one\ntwo\n\na\n\nb"


def test_adf_round_trips_paragraphs() -> None:
    assert adf_to_text(adf("first\n\nsecond")) == "first\n\nsecond"
    assert adf_to_text("not a node") == ""


@pytest.mark.parametrize(
    "node",
    [
        _node("listItem", _node("paragraph", _text("x"))),
        {"type": "media", "attrs": {"type": "external", "url": "https://example.test/x.png"}},
        _node("bulletList", _node("paragraph", _text("not an item"))),
        _node("paragraph", _node("paragraph", _text("nested"))),
        _node("mediaSingle", _node("paragraph", _text("not media"))),
        _node("rule", _text("rules hold nothing")),
        {"type": "paragraph", "marks": [{"type": "strong"}]},
    ],
)
def test_adf_nodes_in_the_wrong_place_are_refused(
    jira: FakeJiraIssues, node: dict[str, Any]
) -> None:
    jira.add_issue(summary="a")
    doc = {"type": "doc", "version": 1, "content": [node]}
    assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": doc}).status == 400


# --- small ----------------------------------------------------------------------------------------


def test_authentication_comes_before_the_unknown_route_404(jira: FakeJiraIssues) -> None:
    assert jira.request("GET", API + "/nothing").status == 401
    assert call(jira, "GET", "/nothing").status == 404
    assert jira.request("GET", "/elsewhere", auth=BASIC).status == 404


def test_the_auth_scheme_is_case_insensitive(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert call(jira, "GET", "/issue/SYN-1", auth=BASIC.replace("Basic", "basic")).status == 200
    assert call(jira, "GET", "/issue/SYN-1", auth="bearer synthetic-oauth-1").status == 200
    assert call(jira, "GET", "/issue/SYN-1", auth="Token synthetic-oauth-1").status == 401


def test_get_issue_refuses_expand_and_properties(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert call(jira, "GET", "/issue/SYN-1", params={"expand": "names"}).status == 400
    assert call(jira, "GET", "/issue/SYN-1", params={"properties": "*all"}).status == 400


def test_the_401_has_the_documented_departure_shape(jira: FakeJiraIssues) -> None:
    response = jira.request("GET", API + "/issue/SYN-1")
    assert response.body == {"message": "Client must be authenticated to access this resource."}
    assert "WWW-Authenticate" not in response.headers


def test_the_departures_are_listed_in_the_module_docstring() -> None:
    import fakes.jira.issues.server as server

    doc = server.__doc__ or ""
    for phrase in (
        "WWW-Authenticate",
        "api.atlassian.com/ex/jira/{cloudId}/rest/api/3",
        "issue ID\n  ascending",
        "unsourced",
        "swagger-v3.v3.json",
    ):
        assert phrase in doc, phrase


def test_text_contains_and_does_not_contain(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="alpha beta")
    jira.add_issue(summary="gamma")
    jira.add_issue(summary="")
    assert keys(search(jira, "project = SYN AND summary ~ alpha")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND summary !~ alpha")) == ["SYN-2"]
    assert keys(search(jira, "project = SYN AND summary is EMPTY")) == ["SYN-3"]


def test_a_function_is_refused_by_name(jira: FakeJiraIssues) -> None:
    response = search(jira, "project = SYN AND assignee = currentUser()")
    assert response.body["errorMessages"] == [
        "Not modelled by the fake Jira: the function 'currentUser()'."
    ]
    unit = search(jira, "project = SYN AND updated >= -1d")
    assert unit.body["errorMessages"] == ["Not modelled by the fake Jira: the relative date '-1d'."]
    assert (
        "Valid formats include"
        in search(jira, "project = SYN AND created >= nope").body["errorMessages"][0]
    )


def test_dates_accept_only_the_documented_formats(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    for text in ("2026/01/01", "2026-01-01", '"2026/01/01 00:00"', '"2026-01-01 00:00"'):
        assert keys(search(jira, f"project = SYN AND created >= {text}")) == ["SYN-1"], text
    for text in ("01/01/2026", "2026.01.01", '"2026-01-01T00:00"', "20260101"):
        assert search(jira, f"project = SYN AND created >= {text}").status == 400, text


def test_updated_is_a_date_field_with_empty_checks(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert keys(search(jira, "project = SYN AND updated is not EMPTY")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND updated is EMPTY")) == []


def test_date_comparisons_include_or_exclude_the_boundary(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="at midnight")  # created exactly 2026-01-01 00:00:00
    assert keys(search(jira, "project = SYN AND created >= 2026/01/01")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND created <= 2026/01/01")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND created > 2026/01/01")) == []
    assert keys(search(jira, "project = SYN AND created < 2026/01/01")) == []


def test_a_key_comparison_only_matches_its_own_project(jira: FakeJiraIssues) -> None:
    for n in range(3):
        jira.add_issue(summary=f"s{n}")
        jira.add_issue(summary=f"o{n}", project="OTH")
    assert keys(search(jira, "key >= SYN-2")) == ["SYN-2", "SYN-3"]
    assert keys(search(jira, "key < OTH-3")) == ["OTH-1", "OTH-2"]


def test_date_equality_is_refused_as_not_modelled_with_its_reason(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    for clause, op in (
        ("created = 2026-01-01", "="),
        ("updated != 2026-01-01", "!="),
        ("created in (2026-01-01)", "in"),
        ("created not in (2026-01-01)", "not in"),
    ):
        message = search(jira, f"project = SYN AND {clause}").body["errorMessages"]
        field = clause.split()[0]
        assert message == [f"Not modelled by the fake Jira: the operator '{op}' on '{field}'."]


def test_not_is_refused_by_name(jira: FakeJiraIssues) -> None:
    body = search(jira, "project = SYN AND NOT labels = x").body
    assert body["errorMessages"] == ["Not modelled by the fake Jira: NOT."]


def test_adf_document_shape_is_checked(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    para = {"type": "paragraph", "content": [{"type": "text", "text": "x"}]}
    for doc in (
        {"type": "doc", "content": [para]},
        {"type": "doc", "version": 2, "content": [para]},
        {"type": "doc", "version": 1, "content": "no"},
        {"type": "paragraph", "version": 1, "content": [para]},
    ):
        assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": doc}).status == 400
    text = {"type": "text", "text": "x", "marks": 5}
    doc = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [text]}]}
    assert call(jira, "POST", "/issue/SYN-1/comment", json={"body": doc}).status == 400


def test_adf_to_text_puts_paragraphs_of_one_list_item_on_separate_lines() -> None:
    item = _node("listItem", _node("paragraph", _text("a")), _node("paragraph", _text("b")))
    doc = {"type": "doc", "version": 1, "content": [_node("orderedList", item, item)]}
    assert adf_to_text(doc) == "a\nb\na\nb"
