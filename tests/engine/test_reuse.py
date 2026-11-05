"""D2-21: same-patch result reuse for ``review_panel`` and ``agent`` stages, never ``checks``.

Fixtures are synthetic. The stage kind comes from the stage named in the evidence key
``EV#stage#ulid`` looked up in the workflow, never from a name the caller passes.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest
import yaml

from sto.config.schema import Workflow as Graph
from sto.config.schema import load_document
from sto.domain import Subject
from sto.engine.handlers.reuse import (
    PriorResult,
    ReuseDecision,
    decide_reuse,
    parse_evidence_key,
)
from sto.gates.evidence import OLDER_BASE_NOTE, Evidence, Validity

OLD = "a" * 40
NEW = "b" * 40
U1 = "01HZX0000000000000000000A1"
U2 = "01HZX0000000000000000000B2"

DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "Workflow",
    "metadata": {"name": "reuse-flow", "team": "ledger"},
    "limits": {"loops": {"fix": 1}, "max_steps_per_run": 30, "max_run_age": "30d"},
    "start": "panel",
    "stages": {
        "panel": {
            "kind": "review_panel",
            "reviewers": ["security", "style"],
            "required": ["security"],
            "block_on": "high",
            "next": {"clean": "qa", "findings": {"to": "qa", "loop": "fix"}, "degraded": "qa"},
        },
        "qa": {"kind": "agent", "agent": "qa_agent", "next": {"ready": "ci", "blocked": "ci"}},
        "ci": {
            "kind": "checks",
            "source": "ci",
            "required": ["unit"],
            "timeout": "45m",
            "next": {"green": "done", "red": "done"},
        },
        "suite": {
            "kind": "checks",
            "source": "qa_suite",
            "required": "team_default",
            "timeout": "45m",
            "next": {"green": "done", "red": "done"},
        },
        "done": {"kind": "terminal", "result": "done"},
    },
}


def wf(mutate: Callable[[dict[str, Any]], None] | None = None) -> Graph:
    data = copy.deepcopy(DOC)
    if mutate:
        mutate(data)
    doc = load_document(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False))
    assert isinstance(doc, Graph)
    return doc


def subject(head: str = NEW, patch: str = "p1") -> Subject:
    return Subject(
        patch_id=patch,
        ticket_revision="r1",
        head_sha=head,
        evidence_digest="e1",
        attention_digest="a1",
    )


def prior(
    stage: str = "panel",
    *,
    ulid: str = U1,
    tested: str = OLD,
    patch: str = "p1",
    validity: Validity = Validity.SAME_PATCH,
    outcome: str = "clean",
    by: tuple[str, ...] = ("security", "style"),
    read_only: bool = True,
) -> PriorResult:
    return PriorResult(
        key=f"EV#{stage}#{ulid}",
        evidence=Evidence(tested, patch, validity),
        outcome=outcome,
        participants=by,
        read_only=read_only,
    )


W = wf()


def test_a_base_update_reuses_the_review_panel_and_notes_the_older_base() -> None:
    d = decide_reuse(W, "panel", [prior()], subject())
    assert d.reuse is True
    assert d.outcome == "clean"
    assert d.key == f"EV#panel#{U1}"
    assert d.notes == (OLDER_BASE_NOTE,)


def test_a_base_update_reuses_an_agent_qa_stage() -> None:
    d = decide_reuse(W, "qa", [prior("qa", outcome="ready", by=("qa_agent",))], subject())
    assert d.reuse is True
    assert d.outcome == "ready"


def test_findings_are_reused_too() -> None:
    assert decide_reuse(W, "panel", [prior(outcome="findings")], subject()).reuse is True


def test_the_same_sha_reuses_with_no_older_base_note() -> None:
    d = decide_reuse(W, "panel", [prior(tested=NEW)], subject())
    assert d.reuse is True
    assert d.notes == ()


@pytest.mark.parametrize("stage", ["panel", "qa"])
def test_a_changed_patch_reuses_nothing(stage: str) -> None:
    by = ("security", "style") if stage == "panel" else ("qa_agent",)
    outcome = "clean" if stage == "panel" else "ready"
    d = decide_reuse(W, stage, [prior(stage, patch="p0", by=by, outcome=outcome)], subject())
    assert d.reuse is False
    assert d.reason == "patch_changed"
    assert d.outcome is None


@pytest.mark.parametrize("stage", ["ci", "suite"])
def test_checks_stages_are_never_reused_even_for_the_same_patch(stage: str) -> None:
    d = decide_reuse(W, stage, [prior(stage, outcome="green", by=())], subject())
    assert d.reuse is False
    assert d.reason == "checks_never_reused"


def test_checks_are_refused_by_the_stage_in_the_key_not_the_name_asked_for() -> None:
    # Asking as "panel" with a record whose key says the checks stage "ci": refused, as checks.
    d = decide_reuse(W, "panel", [prior("ci", outcome="green", by=())], subject())
    assert d.reuse is False
    assert d.reason == "checks_never_reused"


def test_a_key_for_another_review_stage_is_not_reused_here() -> None:
    d = decide_reuse(W, "qa", [prior("panel")], subject())
    assert d.reuse is False
    assert d.reason == "stage_mismatch"


def test_a_stage_the_workflow_does_not_have_is_refused() -> None:
    d = decide_reuse(W, "gone", [prior("gone")], subject())
    assert d.reuse is False
    assert d.reason == "unknown_stage"


def test_a_stage_kind_that_cannot_be_reused_is_refused() -> None:
    d = decide_reuse(W, "done", [prior("done", by=())], subject())
    assert d.reuse is False
    assert d.reason == "kind_not_reusable"


def test_a_new_required_reviewer_is_not_reused_away() -> None:
    w = wf(
        lambda d: d["stages"]["panel"].update(
            reviewers=["security", "style", "perf"], required=["security", "perf"]
        )
    )
    d = decide_reuse(w, "panel", [prior()], subject())
    assert d.reuse is False
    assert d.reason == "reviewer_set_changed"


def test_a_new_optional_reviewer_also_re_runs() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(reviewers=["security", "style", "perf"]))
    assert decide_reuse(w, "panel", [prior()], subject()).reason == "reviewer_set_changed"


def test_a_dropped_reviewer_re_runs() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(reviewers=["security"]))
    assert decide_reuse(w, "panel", [prior()], subject()).reason == "reviewer_set_changed"


def test_reviewer_order_does_not_matter() -> None:
    d = decide_reuse(W, "panel", [prior(by=("style", "security"))], subject())
    assert d.reuse is True


def test_a_required_reviewer_who_never_ran_is_not_reused() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(reviewers=["style"], required=["security"]))
    d = decide_reuse(w, "panel", [prior(by=("style",))], subject())
    assert d.reuse is False
    assert d.reason == "reviewer_set_changed"


def test_an_agent_that_changed_is_not_reused() -> None:
    w = wf(lambda d: d["stages"]["qa"].update(agent="qa_v2"))
    d = decide_reuse(w, "qa", [prior("qa", outcome="ready", by=("qa_agent",))], subject())
    assert d.reuse is False
    assert d.reason == "agent_changed"


def test_a_stage_that_could_write_code_is_not_reused() -> None:
    p = prior("qa", outcome="ready", by=("qa_agent",), read_only=False)
    d = decide_reuse(W, "qa", [p], subject())
    assert d.reuse is False
    assert d.reason == "not_read_only"


def test_a_degraded_panel_is_re_run() -> None:
    d = decide_reuse(W, "panel", [prior(outcome="degraded")], subject())
    assert d.reuse is False
    assert d.reason == "outcome_not_reusable"


def test_an_outcome_the_stage_has_no_edge_for_is_re_run() -> None:
    d = decide_reuse(W, "qa", [prior("qa", outcome="weird", by=("qa_agent",))], subject())
    assert d.reuse is False
    assert d.reason == "outcome_not_reusable"


@pytest.mark.parametrize("validity", [Validity.EXACT_SHA, Validity.CONTAINS_SHA])
def test_only_same_patch_evidence_is_reusable(validity: Validity) -> None:
    d = decide_reuse(W, "panel", [prior(validity=validity, tested=NEW)], subject())
    assert d.reuse is False
    assert d.reason == "validity_not_same_patch"


def test_no_prior_result_runs() -> None:
    d = decide_reuse(W, "panel", [], subject())
    assert (d.reuse, d.reason) == (False, "no_prior_result")


def test_no_subject_runs() -> None:
    d = decide_reuse(W, "panel", [prior()], None)
    assert (d.reuse, d.reason) == (False, "no_subject")


def test_a_pre_push_subject_still_decides_on_patch() -> None:
    pre = Subject(patch_id="p1", ticket_revision="r1", base_sha=NEW)
    assert decide_reuse(W, "panel", [prior()], pre).reuse is True
    pre2 = Subject(patch_id="p2", ticket_revision="r1", base_sha=NEW)
    assert decide_reuse(W, "panel", [prior()], pre2).reason == "patch_changed"


def test_a_prior_without_evidence_runs() -> None:
    p = prior()
    bad = PriorResult(p.key, None, p.outcome, p.participants, True)  # type: ignore[arg-type]
    assert decide_reuse(W, "panel", [bad], subject()).reason == "no_evidence"


@pytest.mark.parametrize(
    "key",
    [
        "",
        "EV#panel",
        "EV#panel#",
        "EV##" + U1,
        "XX#panel#" + U1,
        f"EV#panel#{U1}#x",
        "EV#panel#lower",
    ],
)
def test_a_malformed_key_runs(key: str) -> None:
    p = prior()
    bad = PriorResult(key, p.evidence, p.outcome, p.participants, True)
    d = decide_reuse(W, "panel", [bad], subject())
    assert (d.reuse, d.reason) == (False, "bad_key")


def test_parse_evidence_key() -> None:
    assert parse_evidence_key(f"EV#panel#{U1}") == ("panel", U1)
    assert parse_evidence_key("EV#panel") is None
    assert parse_evidence_key(None) is None


def test_the_latest_result_decides_and_an_older_one_is_not_a_fallback() -> None:
    older = prior(ulid=U1)
    newer = prior(ulid=U2, patch="p0")  # latest saw a different patch
    d = decide_reuse(W, "panel", [older, newer], subject())
    assert d.reuse is False
    assert d.reason == "patch_changed"
    d2 = decide_reuse(W, "panel", [newer, older], subject())  # input order is irrelevant
    assert d2.reason == "patch_changed"


def test_results_of_other_stages_do_not_hide_this_stages_result() -> None:
    other = prior("qa", ulid=U2, outcome="ready", by=("qa_agent",))
    d = decide_reuse(W, "panel", [prior(ulid=U1), other], subject())
    assert d.reuse is True
    assert d.key == f"EV#panel#{U1}"


def test_the_decision_is_recorded_as_plain_data() -> None:
    d = decide_reuse(W, "panel", [prior()], subject())
    assert d.to_data() == {
        "stage": "panel",
        "reuse": True,
        "reason": "same_patch",
        "evidence": f"EV#panel#{U1}",
        "outcome": "clean",
        "notes": [OLDER_BASE_NOTE],
    }
    r = decide_reuse(W, "panel", [], subject())
    assert r.to_data() == {
        "stage": "panel",
        "reuse": False,
        "reason": "no_prior_result",
        "evidence": None,
        "outcome": None,
        "notes": [],
    }
    json.dumps(d.to_data())


def test_decision_type_is_frozen() -> None:
    d = decide_reuse(W, "panel", [], subject())
    assert isinstance(d, ReuseDecision)
    with pytest.raises(AttributeError):
        d.reuse = True  # type: ignore[misc]


def test_a_panel_whose_required_set_is_all_of_its_reviewers_reuses() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(required=["security", "style"]))
    assert decide_reuse(w, "panel", [prior()], subject()).reuse is True


@pytest.mark.parametrize(
    "bad",
    [
        {"outcome": None},
        {"participants": ["security", "style"]},
        {"participants": ("security", 7)},
        {"participants": ("security", " ")},
    ],
)
def test_a_malformed_record_runs(bad: dict[str, Any]) -> None:
    import dataclasses

    p = dataclasses.replace(prior(), **bad)
    d = decide_reuse(W, "panel", [p], subject())
    assert (d.reuse, d.reason) == (False, "bad_record")


def test_a_non_record_candidate_runs() -> None:
    d = decide_reuse(W, "panel", [object()], subject())  # type: ignore[list-item]
    assert d.reuse is False


@pytest.mark.parametrize("flag", [False, 1, None])
def test_read_only_must_be_exactly_true(flag: object) -> None:
    import dataclasses

    p = dataclasses.replace(prior("qa", outcome="ready", by=("qa_agent",)), read_only=flag)  # type: ignore[arg-type]
    assert decide_reuse(W, "qa", [p], subject()).reason == "not_read_only"


def test_a_prior_result_is_frozen() -> None:
    p = prior()
    with pytest.raises(AttributeError):
        p.outcome = "findings"  # type: ignore[misc]
