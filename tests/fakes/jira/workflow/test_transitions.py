"""D6-09: transitions and screens. Each case follows the Get transitions and Transition issue
pages (cited in ``model.py``/``server.py``); fixtures are synthetic."""

from __future__ import annotations

from typing import Any

import pytest

from fakes.jira.issues import BASIC, RateShape
from fakes.jira.workflow import SERVICE, SOFTWARE, FakeJiraWorkflow

API = "/rest/api/3"


@pytest.fixture
def jira() -> FakeJiraWorkflow:
    return FakeJiraWorkflow()  # SYN uses SOFTWARE, OTH uses SERVICE


def call(jira: FakeJiraWorkflow, method: str, path: str, **kw: Any) -> Any:
    kw.setdefault("auth", BASIC)
    return jira.request(method, API + path, **kw)


def transitions(jira: FakeJiraWorkflow, key: str, **params: Any) -> list[dict[str, Any]]:
    r = call(jira, "GET", f"/issue/{key}/transitions", params=params)
    assert r.status == 200
    return list(r.body["transitions"])


def by_target(jira: FakeJiraWorkflow, key: str, target: str) -> str:
    (found,) = [t for t in transitions(jira, key) if t["to"]["name"] == target]
    return str(found["id"])


def move(jira: FakeJiraWorkflow, key: str, tid: str, **body: Any) -> Any:
    return call(jira, "POST", f"/issue/{key}/transitions", json={"transition": {"id": tid}, **body})


def status(jira: FakeJiraWorkflow, key: str) -> str:
    return str(call(jira, "GET", f"/issue/{key}").body["fields"]["status"]["name"])


def test_transition_ids_differ_across_two_workflows(jira: FakeJiraWorkflow) -> None:
    a = jira.add_issue(summary="a", project="SYN")["key"]
    b = jira.add_issue(summary="b", project="OTH")["key"]
    started = jira.add_issue(summary="c", project="SYN", status="In Progress")["key"]
    # the same target status is reached by different transition IDs ...
    assert by_target(jira, started, "Done") == "21"
    assert by_target(jira, b, "Done") == "11"
    # ... and the same ID means different things: a hard-coded ID is the wrong adapter
    assert {t["id"]: t["to"]["name"] for t in transitions(jira, a)}["11"] == "In Progress"
    assert {t["id"]: t["to"]["name"] for t in transitions(jira, b)}["11"] == "Done"
    assert SOFTWARE.name != SERVICE.name


def test_transition_ids_are_strings_and_shape_is_documented(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    r = call(jira, "GET", f"/issue/{key}/transitions")
    assert set(r.body) == {"expand", "transitions"} or set(r.body) == {"transitions"}
    first = r.body["transitions"][0]
    assert isinstance(first["id"], str)
    assert {"name", "to", "hasScreen", "isGlobal", "isInitial", "isAvailable"} <= set(first)
    assert first["to"]["statusCategory"]["key"] in {"new", "indeterminate", "done"}
    assert "fields" not in first  # only with expand=transitions.fields


def test_get_transitions_lists_only_what_the_status_allows(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", project="OTH", status="In Review")["key"]
    names = {t["name"] for t in transitions(jira, key)}
    assert names == {"Approve", "Back to To Do"}  # one local, one global


def test_expand_fields_reports_the_screen(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", status="In Progress")["key"]
    done = next(
        t for t in transitions(jira, key, expand="transitions.fields") if t["name"] == "Done"
    )
    assert done["hasScreen"] is True
    field = done["fields"]["resolution"]
    assert field["required"] is True
    assert field["name"] == "Resolution"
    assert field["key"] == "resolution"
    assert field["operations"] == ["set"]
    assert {v["name"] for v in field["allowedValues"]} == {"Done", "Won't Do"}
    todo = jira.add_issue(summary="b")["key"]
    start = next(t for t in transitions(jira, todo, expand="transitions.fields") if t["id"] == "11")
    assert start["hasScreen"] is False
    assert start["fields"] == {}


def test_unknown_transition_id_filter_gives_an_empty_list(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]  # spec: a transition that cannot be performed
    assert transitions(jira, key, transitionId="999") == []
    assert [t["id"] for t in transitions(jira, key, transitionId="11")] == ["11"]
    assert transitions(jira, key, transitionId="21") == []  # real, but not from To Do


def test_required_screen_field_fails_as_documented(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", status="In Progress")["key"]
    r = move(jira, key, "21")
    assert r.status == 400
    assert r.body == {"errorMessages": [], "errors": {"resolution": "Resolution is required."}}
    assert status(jira, key) == "In Progress"  # nothing applied


def test_required_custom_field_on_the_other_workflow(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", project="OTH")["key"]
    r = move(jira, key, "11")
    assert r.status == 400
    assert r.body["errors"] == {"customfield_10050": "Root cause is required."}
    assert move(jira, key, "11", fields={"customfield_10050": "synthetic"}).status == 204
    got = call(jira, "GET", f"/issue/{key}").body["fields"]
    assert got["status"]["name"] == "Done"
    assert got["customfield_10050"] == "synthetic"


def test_required_field_with_a_blank_value_still_fails(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", project="OTH")["key"]
    r = move(jira, key, "11", fields={"customfield_10050": "  "})
    assert r.status == 400
    assert "customfield_10050" in r.body["errors"]


def test_transition_with_a_valid_screen_value(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", status="In Progress")["key"]
    assert move(jira, key, "21", fields={"resolution": {"name": "Done"}}).status == 204
    f = call(jira, "GET", f"/issue/{key}").body["fields"]
    assert f["status"]["name"] == "Done"
    assert f["status"]["statusCategory"]["key"] == "done"
    assert f["resolution"]["name"] == "Done"


def test_resolution_by_id_and_via_update(jira: FakeJiraWorkflow) -> None:
    one = jira.add_issue(summary="a", status="In Progress")["key"]
    assert move(jira, one, "21", fields={"resolution": {"id": "10001"}}).status == 204
    two = jira.add_issue(summary="b", status="In Progress")["key"]
    assert move(jira, two, "21", update={"resolution": [{"set": {"name": "Done"}}]}).status == 204


@pytest.mark.parametrize("value", [{"name": "Nope"}, {"id": "1"}, "Done", 7, None, {}])
def test_invalid_option_value_is_rejected(jira: FakeJiraWorkflow, value: Any) -> None:
    key = jira.add_issue(summary="a", status="In Progress")["key"]
    r = move(jira, key, "21", fields={"resolution": value})
    assert r.status == 400
    assert "resolution" in r.body["errors"]
    assert status(jira, key) == "In Progress"


def test_field_not_on_the_screen_is_refused(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    r = move(jira, key, "11", fields={"customfield_10050": "x"})  # a screen-less transition
    assert r.status == 400
    assert r.body["errors"] == {
        "customfield_10050": (
            "Field 'customfield_10050' cannot be set. It is not on the appropriate screen, "
            "or unknown."
        )
    }
    assert status(jira, key) == "To Do"


def test_field_in_both_fields_and_update_is_refused(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", status="In Progress")["key"]
    r = move(
        jira,
        key,
        "21",
        fields={"resolution": {"name": "Done"}},
        update={"resolution": [{"set": {"name": "Done"}}]},
    )
    assert r.status == 400
    assert "resolution" in r.body["errors"]


def test_missing_or_malformed_transition_is_a_400(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    bodies: list[Any] = [{}, {"transition": {}}, {"transition": {"id": 11}}, {"transition": "11"}]
    for body in bodies:
        r = call(jira, "POST", f"/issue/{key}/transitions", json=body)
        assert r.status == 400, body
        assert r.body["errorMessages"], body


def test_a_transition_not_available_from_the_status_is_a_400(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    r = move(jira, key, "21")  # In Progress to Done: not from To Do
    assert r.status == 400
    assert r.body["errorMessages"]
    assert status(jira, key) == "To Do"
    assert move(jira, key, "999").status == 400


def test_moving_to_the_status_it_is_already_in_is_a_400(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    assert move(jira, key, "11").status == 204
    assert move(jira, key, "11").status == 400  # the adapter must read state first


def test_unknown_issue_is_404_and_denied_project_is_404(jira: FakeJiraWorkflow) -> None:
    assert call(jira, "GET", "/issue/SYN-99/transitions").status == 404
    assert move(jira, "SYN-99", "11").status == 404
    key = jira.add_issue(summary="a")["key"]
    jira.deny_project("SYN")
    assert call(jira, "GET", f"/issue/{key}/transitions").status == 404
    assert move(jira, key, "11").status == 404


def test_unmodelled_inputs_are_refused_not_ignored(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    for params in ({"expand": "nope"}, {"includeUnavailableTransitions": "maybe"}):
        assert call(jira, "GET", f"/issue/{key}/transitions", params=params).status == 400
    extras: list[dict[str, Any]] = [{"historyMetadata": {}}, {"properties": []}]
    for extra in extras:
        assert move(jira, key, "11", **extra).status == 400
    assert status(jira, key) == "To Do"


def test_a_failed_condition_hides_the_transition(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", project="OTH", assignee=None)["key"]
    assert "Start review" not in {t["name"] for t in transitions(jira, key)}
    shown = transitions(jira, key, includeUnavailableTransitions="true")
    review = next(t for t in shown if t["name"] == "Start review")
    assert review["isAvailable"] is False
    assert review["isConditional"] is True
    assert move(jira, key, review["id"]).status == 400
    jira.request(
        "PUT",
        f"{API}/issue/{key}",
        auth=BASIC,
        json={"fields": {"assignee": {"accountId": "5bsynthetic0001"}}},
    )
    assert move(jira, key, review["id"]).status == 204


def test_a_global_transition_works_from_any_status(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a", project="OTH", status="In Review")["key"]
    back = next(t for t in transitions(jira, key) if t["isGlobal"])
    assert move(jira, key, back["id"]).status == 204
    assert status(jira, key) == "To Do"


def test_transition_updates_the_issue_and_is_searchable(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    before = call(jira, "GET", f"/issue/{key}").body["fields"]["updated"]
    jira.now += 60
    assert move(jira, key, "11").status == 204
    after = call(jira, "GET", f"/issue/{key}").body["fields"]["updated"]
    assert after > before
    r = call(
        jira, "POST", "/search/jql", json={"jql": 'status = "In Progress"', "fields": ["status"]}
    )
    assert [i["key"] for i in r.body["issues"]] == [key]
    r = call(jira, "POST", "/search/jql", json={"jql": 'status = "To Do"', "fields": ["status"]})
    assert r.body["issues"] == []


def test_concurrent_change_wins_over_a_stale_id(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    stale = by_target(jira, key, "In Progress")
    jira.force_status(key, "In Progress")  # a person moved it in the UI after our read
    assert move(jira, key, stale).status == 400
    assert by_target(jira, key, "Done") == "21"


def test_inherited_behaviours_still_apply(jira: FakeJiraWorkflow) -> None:
    key = jira.add_issue(summary="a")["key"]
    assert call(jira, "GET", f"/issue/{key}/transitions", auth=None).status == 401
    jira.rate_limit_next(1, RateShape.PRIMARY_429, "do_transition")
    limited = move(jira, key, "11")
    assert limited.status == 429
    assert int(limited.headers["Retry-After"]) > 0
    assert status(jira, key) == "To Do"
    jira.respond_next("do_transition", 409)  # "conflicting update", documented
    assert move(jira, key, "11").status == 409
    jira.fault_next("do_transition", "lose")  # applied, but the caller sees a timeout
    with pytest.raises(TimeoutError):
        move(jira, key, "11")
    assert status(jira, key) == "In Progress"


def test_two_projects_one_workflow_and_remapping(jira: FakeJiraWorkflow) -> None:
    jira.assign_workflow("OTH", SOFTWARE)
    key = jira.add_issue(summary="a", project="OTH")["key"]
    assert {t["id"] for t in transitions(jira, key)} == {"11"}
