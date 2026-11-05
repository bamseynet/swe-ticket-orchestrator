"""D6-01 pass 2: EMPTY as a keyword, priority order, registered values, returnIssue, body shapes,
token checks and the departures that were documented rather than fixed.

Fixtures are synthetic. "Spec" is the v3 OpenAPI document cited in ``server.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from fakes.jira.issues import BASIC, FakeJiraIssues, Response, adf
from fakes.jira.issues.server import ACCOUNT_ID, OTHER_ACCOUNT_ID

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


def message(response: Response) -> str:
    assert response.status == 400
    return str(response.body["errorMessages"][0])


# --- 1: EMPTY and NULL are keywords with =, !=, in and not in ---------------------------------


def seeded_empty(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="none", labels=[], assignee=None)
    jira.add_issue(summary="labelled", labels=["x"], assignee=OTHER_ACCOUNT_ID)
    jira.add_issue(summary="literal", labels=["empty"])


def test_equals_empty_is_the_same_as_is_empty(jira: FakeJiraIssues) -> None:
    seeded_empty(jira)
    assert keys(search(jira, "project = SYN AND labels = EMPTY")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND labels = null")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND labels is EMPTY")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND assignee = EMPTY")) == ["SYN-1"]


def test_not_equals_empty_is_the_same_as_is_not_empty(jira: FakeJiraIssues) -> None:
    seeded_empty(jira)
    assert keys(search(jira, "project = SYN AND labels != EMPTY")) == ["SYN-2", "SYN-3"]
    assert keys(search(jira, "project = SYN AND assignee != EMPTY")) == ["SYN-2", "SYN-3"]


def test_in_and_not_in_treat_empty_as_the_keyword(jira: FakeJiraIssues) -> None:
    seeded_empty(jira)
    both = f"project = SYN AND assignee in (EMPTY, {OTHER_ACCOUNT_ID})"
    assert keys(search(jira, both)) == ["SYN-1", "SYN-2"]
    assert keys(search(jira, "project = SYN AND labels in (EMPTY)")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND labels not in (EMPTY, x)")) == ["SYN-3"]
    assert keys(search(jira, "project = SYN AND labels not in (EMPTY)")) == ["SYN-2", "SYN-3"]


def test_a_quoted_empty_and_a_summary_search_are_literals(jira: FakeJiraIssues) -> None:
    seeded_empty(jira)
    assert keys(search(jira, 'project = SYN AND labels = "empty"')) == ["SYN-3"]
    assert keys(search(jira, "project = SYN AND labels = 'EMPTY'")) == ["SYN-3"]
    jira.add_issue(summary="an empty summary word")
    jira.add_issue(summary="null and void")
    assert keys(search(jira, "project = SYN AND summary ~ EMPTY")) == ["SYN-4"]
    assert keys(search(jira, "project = SYN AND summary !~ null")) == [
        "SYN-1",
        "SYN-2",
        "SYN-3",
        "SYN-4",
    ]


def test_empty_cannot_be_ordered_against(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert search(jira, "key >= EMPTY").status == 400


# --- 2: ORDER BY priority runs highest to lowest when descending ------------------------------


def test_order_by_priority_desc_is_highest_first_and_asc_lowest_first(jira: FakeJiraIssues) -> None:
    for level in ("Low", "Highest", "Medium", "Lowest", "High"):
        jira.add_issue(summary=level, priority=level)
    desc = keys(search(jira, "project = SYN ORDER BY priority DESC"))
    assert desc == ["SYN-2", "SYN-5", "SYN-3", "SYN-1", "SYN-4"]
    asc = keys(search(jira, "project = SYN ORDER BY priority ASC"))
    assert asc == ["SYN-4", "SYN-1", "SYN-3", "SYN-5", "SYN-2"]


def test_equal_issues_stay_in_id_order_whatever_the_direction(jira: FakeJiraIssues) -> None:
    for level in ("Low", "High", "Low", "High", "Low"):
        jira.add_issue(summary=level, priority=level)
    desc = keys(search(jira, "project = SYN ORDER BY priority DESC"))
    assert desc == ["SYN-2", "SYN-4", "SYN-1", "SYN-3", "SYN-5"]
    asc = keys(search(jira, "project = SYN ORDER BY priority ASC"))
    assert asc == ["SYN-1", "SYN-3", "SYN-5", "SYN-2", "SYN-4"]


# --- 3: registering values without an issue ---------------------------------------------------


def test_a_registered_status_priority_and_account_can_be_named_in_jql(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    for clause in (
        'status = "In Review"',
        "priority = Urgent",
        "assignee = 5bsynthetic0003",
    ):
        refused = search(jira, f"project = SYN AND {clause}")
        assert "does not exist for the field" in message(refused)
    jira.add_status("In Review")
    jira.add_priority("Urgent")
    jira.add_account("5bsynthetic0003")
    for clause in (
        'status = "In Review"',
        "priority = Urgent",
        "assignee = 5bsynthetic0003",
    ):
        assert keys(search(jira, f"project = SYN AND {clause}")) == []


def test_registered_values_work_on_issues_and_edits(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.add_priority("Urgent")
    jira.add_account("5bsynthetic0003")
    edit = {
        "fields": {"priority": {"name": "Urgent"}, "assignee": {"accountId": "5bsynthetic0003"}}
    }
    assert call(jira, "PUT", "/issue/SYN-1", json=edit).status == 204
    assert keys(search(jira, "priority = Urgent")) == ["SYN-1"]
    assert keys(search(jira, "assignee = 5bsynthetic0003")) == ["SYN-1"]
    jira.add_status("In Review")
    assert jira._statuses["in review"] == "10100" or jira._statuses["in review"].isdigit()


# --- 4: ids for priority and status; aliases and emails are not modelled ----------------------


def test_priority_and_status_are_accepted_by_id_in_jql(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", priority="High", status="In Progress")
    jira.add_issue(summary="b", priority="Low", status="Done")
    assert keys(search(jira, "project = SYN AND priority = 2")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND priority in (2, 4)")) == ["SYN-1", "SYN-2"]
    assert keys(search(jira, "project = SYN AND status = 3")) == ["SYN-1"]
    assert keys(search(jira, "project = SYN AND status = 10001")) == ["SYN-2"]
    assert keys(search(jira, "project = SYN AND issuetype = 10001")) == ["SYN-1", "SYN-2"]


@pytest.mark.parametrize(
    ("clause", "what"),
    [
        ("type = Task", "the field 'type'"),
        ("issuekey = SYN-1", "the field 'issuekey'"),
        ("duedate is EMPTY", "the field 'duedate'"),
        ('assignee = "bot@example.test"', "a user given by email address"),
        ('reporter = "bot@example.test"', "a user given by email address"),
    ],
)
def test_aliases_standard_fields_and_emails_are_not_modelled(
    jira: FakeJiraIssues, clause: str, what: str
) -> None:
    jira.add_issue(summary="a")
    assert message(search(jira, f"project = SYN AND {clause}")) == (
        f"Not modelled by the fake Jira: {what}."
    )


def test_order_by_a_standard_field_is_not_modelled(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert "Not modelled" in message(search(jira, "project = SYN ORDER BY duedate"))


# --- 5, 3, nits: departures are documented ----------------------------------------------------


def test_the_jql_departures_are_documented() -> None:
    import fakes.jira.issues.jql as jql

    doc = jql.__doc__ or ""
    for phrase in (
        "validateQuery",
        "key = SYN-999",
        "project = OTH",
        "Empty values sort first under ``ORDER BY assignee``",
        "``status``\n  sorts by name",
        "add_status",
    ):
        assert phrase in doc, phrase


def test_the_server_departures_are_documented() -> None:
    import fakes.jira.issues.server as server

    doc = server.__doc__ or ""
    for phrase in (
        "strictly after that position",
        "before it (created mid-paging under ``DESC``) is not",
        "comment ``maxResults`` cap of 100 is unsourced",
        "case-sensitive",
        "returnIssue=true",
        "``updateHistory`` on create",
    ):
        assert phrase in doc, phrase
    assert "neither skipped nor repeated" not in doc


def test_a_key_that_does_not_exist_and_a_denied_project_answer_empty_in_jql(
    jira: FakeJiraIssues,
) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b", project="OTH")
    jira.deny_project("OTH")
    assert keys(search(jira, "key = SYN-999")) == []
    assert keys(search(jira, "project = OTH")) == []
    assert call(jira, "GET", "/issue/OTH-1").status == 404


def test_path_keys_are_case_sensitive_and_lowercase_create_values_are_refused(
    jira: FakeJiraIssues,
) -> None:
    jira.add_issue(summary="a")
    assert call(jira, "GET", "/issue/syn-1").status == 404
    base = {"summary": "x", "issuetype": {"name": "Task"}}
    lower = {"fields": {**base, "project": {"key": "syn"}}}
    assert call(jira, "POST", "/issue", json=lower).status == 400
    as_int = {"fields": {**base, "project": {"id": 10000}}}
    assert call(jira, "POST", "/issue", json=as_int).status == 400
    by_id = {"fields": {**base, "project": {"key": "SYN"}, "assignee": {"id": ACCOUNT_ID}}}
    assert call(jira, "POST", "/issue", json=by_id).status == 400


# --- 6: returnIssue and the parameters that are not modelled ----------------------------------


def test_edit_with_return_issue_gives_the_edited_issue(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="old")
    body = {"fields": {"summary": "new"}}
    for flag in ("true", True, "TRUE"):
        response = call(jira, "PUT", "/issue/SYN-1", params={"returnIssue": flag}, json=body)
        assert response.status == 200
        assert response.body["key"] == "SYN-1"
        assert response.body["fields"]["summary"] == "new"
    for off in ("false", False, None):
        assert (
            call(jira, "PUT", "/issue/SYN-1", params={"returnIssue": off}, json=body).status == 204
        )
    assert (
        call(jira, "PUT", "/issue/SYN-1", params={"returnIssue": "maybe"}, json=body).status == 400
    )


def test_a_refused_edit_with_return_issue_is_still_a_400(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="old")
    body = {"fields": {"summary": ""}}
    assert (
        call(jira, "PUT", "/issue/SYN-1", params={"returnIssue": "true"}, json=body).status == 400
    )


def test_expand_and_update_history_are_refused_as_not_modelled(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    cid = call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf("x")}).body["id"]
    new_issue = {
        "fields": {"project": {"key": "SYN"}, "summary": "x", "issuetype": {"name": "Task"}}
    }
    refused = [
        call(jira, "PUT", "/issue/SYN-1", params={"expand": "names"}, json={}),
        call(
            jira,
            "POST",
            "/issue/SYN-1/comment",
            params={"expand": "renderedBody"},
            json={"body": adf("y")},
        ),
        call(
            jira,
            "PUT",
            f"/issue/SYN-1/comment/{cid}",
            params={"expand": "renderedBody"},
            json={"body": adf("z")},
        ),
        call(jira, "POST", "/issue", params={"updateHistory": "true"}, json=new_issue),
    ]
    for response in refused:
        assert "Not modelled by the fake Jira" in message(response)
    assert call(jira, "GET", "/issue/SYN-1/comment").body["total"] == 1


def test_harmless_edit_parameters_are_accepted(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    params = {"notifyUsers": "false", "overrideScreenSecurity": "false"}
    assert call(jira, "PUT", "/issue/SYN-1", params=params, json={}).status == 204


# --- 7: a body that is not a JSON object ------------------------------------------------------


@pytest.mark.parametrize("body", [["x"], "text", 5, True, [], "", 0, False])
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/search/jql"),
        ("POST", "/issue"),
        ("PUT", "/issue/SYN-1"),
        ("POST", "/issue/SYN-1/comment"),
        ("PUT", "/issue/SYN-1/comment/20001"),
    ],
)
def test_a_body_that_is_not_an_object_is_a_400_never_an_exception(
    jira: FakeJiraIssues, method: str, path: str, body: Any
) -> None:
    jira.add_issue(summary="a")
    call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf("x")})
    response = call(jira, method, path, json=body)
    assert response.status == 400
    assert response.body["errorMessages"] == ["Request body must be a JSON object."]


def test_a_non_object_body_is_checked_after_authentication(jira: FakeJiraIssues) -> None:
    assert jira.request("POST", API + "/search/jql", json=["x"]).status == 401


def test_an_empty_object_body_still_reaches_the_handler(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    assert call(jira, "PUT", "/issue/SYN-1", json={}).status == 204
    assert call(jira, "POST", "/search/jql", json={}).status == 400  # unbounded


# --- 9: more forged tokens --------------------------------------------------------------------


def _forged(jira: FakeJiraIssues, jql: str, **override: Any) -> str:
    digest = hashlib.sha256(jql.encode()).hexdigest()[:12]
    body = {"q": digest, "e": 0, "p": 1, "t": jira.now, "k": [10001], **override}
    return base64.urlsafe_b64encode(json.dumps(body).encode()).decode()


@pytest.mark.parametrize(
    ("jql", "override"),
    [
        ("project = SYN", {"k": ["x"]}),
        ("project = SYN", {"k": [1, 2]}),
        ("project = SYN", {"k": [True]}),
        ("project = SYN ORDER BY created", {"k": [10001]}),
        ("project = SYN ORDER BY created DESC", {"k": ["2026", "x"]}),
        ("project = SYN", {"t": float("nan")}),
        ("project = SYN", {"t": float("inf")}),
        ("project = SYN", {"t": True}),
        ("project = SYN", {"e": True}),
    ],
)
def test_forged_tokens_with_a_wrong_position_or_time_are_refused(
    jira: FakeJiraIssues, jql: str, override: dict[str, Any]
) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b")
    assert search(jira, jql, nextPageToken=_forged(jira, jql, **override)).status == 400


def test_a_nan_token_time_cannot_make_a_token_immortal(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b")
    jira.now += 10 * 24 * 3600
    forged = _forged(jira, "project = SYN", t=float("nan"))
    assert search(jira, "project = SYN", nextPageToken=forged).status == 400


def test_a_forged_token_with_the_right_shape_is_the_control(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b")
    jql = "project = SYN ORDER BY created"
    good = _forged(jira, jql, k=["2026-01-01T00:00:00.000+0000", 10001])
    assert keys(search(jira, jql, nextPageToken=good)) == ["SYN-2"]


# --- 10: standard fields are "not modelled" ---------------------------------------------------


def test_standard_fields_are_not_modelled_and_custom_ones_are_unknown(
    jira: FakeJiraIssues,
) -> None:
    jira.add_issue(summary="a")
    standard = call(jira, "PUT", "/issue/SYN-1", json={"fields": {"duedate": "2026-02-01"}})
    assert standard.body["errors"] == {
        "duedate": "Field 'duedate' is a standard Jira field that the fake Jira does not model."
    }
    custom = call(jira, "PUT", "/issue/SYN-1", json={"fields": {"customfield_1": "x"}})
    assert custom.body["errors"]["customfield_1"].endswith("or unknown.")
    update = call(jira, "PUT", "/issue/SYN-1", json={"update": {"components": [{"set": []}]}})
    assert "standard Jira field" in update.body["errors"]["components"]
    for name in ("reporter", "fixVersions"):
        made = call(
            jira,
            "POST",
            "/issue",
            json={
                "fields": {
                    "project": {"key": "SYN"},
                    "summary": "x",
                    "issuetype": {"name": "Task"},
                    name: "x",
                }
            },
        )
        assert "standard Jira field" in made.body["errors"][name]


# --- surviving mutants and nits ---------------------------------------------------------------


def test_the_comment_page_size_is_capped_at_100(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    for n in range(120):
        call(jira, "POST", "/issue/SYN-1/comment", json={"body": adf(f"c{n}")})
    page = call(jira, "GET", "/issue/SYN-1/comment", params={"maxResults": "1000"}).body
    assert page["maxResults"] == 100
    assert len(page["comments"]) == 100
    small = call(jira, "GET", "/issue/SYN-1/comment", params={"maxResults": "7"}).body
    assert small["maxResults"] == 7
    assert len(small["comments"]) == 7


def test_duplicate_labels_on_create_and_edit_are_collapsed(jira: FakeJiraIssues) -> None:
    fields = {
        "project": {"key": "SYN"},
        "summary": "x",
        "issuetype": {"name": "Task"},
        "labels": ["a", "b", "a"],
    }
    made = call(jira, "POST", "/issue", json={"fields": fields})
    assert made.status == 201
    assert jira._issues["SYN-1"]["fields"]["labels"] == ["a", "b"]
    call(jira, "PUT", "/issue/SYN-1", json={"fields": {"labels": ["c", "c"]}})
    assert jira._issues["SYN-1"]["fields"]["labels"] == ["c"]


def test_label_set_takes_a_list_not_a_bare_string(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a", labels=["keep"])
    bare = call(jira, "PUT", "/issue/SYN-1", json={"update": {"labels": [{"set": "solo"}]}})
    assert bare.status == 400
    assert jira._issues["SYN-1"]["fields"]["labels"] == ["keep"]
    ok = call(jira, "PUT", "/issue/SYN-1", json={"update": {"labels": [{"set": ["solo"]}]}})
    assert ok.status == 204
    assert jira._issues["SYN-1"]["fields"]["labels"] == ["solo"]


def test_a_custom_priority_sorts_below_lowest(jira: FakeJiraIssues) -> None:
    jira.add_priority("Urgent")
    jira.add_issue(summary="a", priority="Lowest")
    jira.add_issue(summary="b", priority="Urgent")
    jira.add_issue(summary="c", priority="Highest")
    assert keys(search(jira, "project = SYN ORDER BY priority ASC")) == ["SYN-2", "SYN-1", "SYN-3"]


def test_a_boolean_token_epoch_is_not_the_number_one(jira: FakeJiraIssues) -> None:
    jira.add_issue(summary="a")
    jira.add_issue(summary="b")
    jira.expire_page_tokens()  # the epoch is now 1, which True == 1 would match
    forged = _forged(jira, "project = SYN", e=True)
    assert search(jira, "project = SYN", nextPageToken=forged).status == 400
    assert keys(
        search(jira, "project = SYN", nextPageToken=_forged(jira, "project = SYN", e=1))
    ) == ["SYN-2"]
