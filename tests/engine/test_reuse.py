"""D2-21: same-patch result reuse for ``review_panel`` and QA ``agent`` stages, never ``checks``.

Fixtures are synthetic. The stage kind comes from the stage named in the evidence key
``EV#stage#ulid`` looked up in the workflow, never from a name the caller passes. The manifest is
the real catalog: a QA agent has ``record_evidence``, and writing is ``workspace.write``.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from collections.abc import Callable
from typing import Any

import pytest
import yaml

from sto.agents.prompts.render import PromptTemplate
from sto.config.manifest import Manifest, load_manifest
from sto.config.schema import Workflow as Graph
from sto.config.schema import load_document
from sto.domain import Subject
from sto.engine.handlers.reuse import (
    PriorResult,
    ReuseDecision,
    decide_reuse,
    parse_evidence_key,
    stage_digest,
)
from sto.gates.evidence import OLDER_BASE_NOTE, Evidence, Validity

OLD = "a" * 40
NEW = "b" * 40
U1 = "01HZX0000000000000000000A1"
U2 = "01HZX0000000000000000000B2"
PART = "TEAM#t1#RUN#r1"
MAN: Manifest = load_manifest()
PANEL_BY = ("correctness_reviewer", "security_reviewer")
PROMPTS: dict[str, PromptTemplate] = {
    name: PromptTemplate(name=name, version="1", text=f"You are {name}.")
    for name in (*PANEL_BY, "qa_agent", "triage")
}

DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "Workflow",
    "metadata": {"name": "reuse-flow", "team": "ledger"},
    "limits": {"loops": {"fix": 1}, "max_steps_per_run": 30, "max_run_age": "30d"},
    "start": "panel",
    "stages": {
        "panel": {
            "kind": "review_panel",
            "reviewers": list(PANEL_BY),
            "required": ["security_reviewer"],
            "block_on": "high",
            "next": {"clean": "qa", "findings": {"to": "qa", "loop": "fix"}, "degraded": "qa"},
        },
        "qa": {
            "kind": "agent",
            "agent": "qa_agent",
            "next": {"pass": "ci", "fail": "ci", "inconclusive": "ci"},
        },
        "triage": {
            "kind": "agent",
            "agent": "triage",
            "next": {"ready": "ci", "needs_info": "ci", "not_actionable": "ci"},
        },
        "impl": {"kind": "agent", "agent": "implementer", "next": {"ready": "ci", "blocked": "ci"}},
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


W = wf()


def subject(head: str = NEW, patch: str = "p1", rev: str = "r1") -> Subject:
    return Subject(
        patch_id=patch,
        ticket_revision=rev,
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
    outcome: str | None = None,
    by: tuple[str, ...] | None = None,
    read_only: bool = True,
    graph: Graph = W,
    digest: str | None = "auto",
    partition: str | None = PART,
    rev: str | None = "r1",
) -> PriorResult:
    if outcome is None:
        outcome = "clean" if stage == "panel" else "pass"
    if by is None:
        by = (
            PANEL_BY
            if stage == "panel"
            else {"qa": ("qa_agent",), "triage": ("triage",)}.get(stage, ())
        )
    if digest == "auto":
        digest = stage_digest(graph, MAN, stage, PROMPTS)
    return PriorResult(
        key=f"EV#{stage}#{ulid}",
        evidence=Evidence(tested, patch, validity),
        outcome=outcome,
        participants=by,
        read_only=read_only,
        config_digest=digest,
        partition=partition,
        ticket_revision=rev,
    )


def decide(
    stage: str,
    cands: list[PriorResult],
    sub: Subject | None = None,
    graph: Graph = W,
    partition: str = PART,
) -> ReuseDecision:
    return decide_reuse(
        graph,
        MAN,
        stage,
        cands,
        subject() if sub is None else sub,
        partition,
        prompts=PROMPTS,
    )


# --- the three acceptance criteria ---------------------------------------------------------


def test_a_base_update_reuses_the_review_panel_and_names_the_older_base() -> None:
    d = decide("panel", [prior()])
    assert d.reuse is True
    assert d.outcome == "clean"
    assert d.key == f"EV#panel#{U1}"
    assert d.notes == (f"{OLDER_BASE_NOTE} ({OLD})",)


def test_a_base_update_reuses_a_qa_agent_stage() -> None:
    d = decide("qa", [prior("qa")])
    assert d.reuse is True
    assert d.outcome == "pass"


def test_a_failed_qa_result_is_reused_too() -> None:
    assert decide("qa", [prior("qa", outcome="fail")]).reuse is True


def test_findings_are_reused_too() -> None:
    assert decide("panel", [prior(outcome="findings")]).reuse is True


def test_the_same_sha_reuses_with_no_older_base_note() -> None:
    d = decide("panel", [prior(tested=NEW)])
    assert d.reuse is True
    assert d.notes == ()


@pytest.mark.parametrize("stage", ["panel", "qa"])
def test_a_changed_patch_reuses_nothing(stage: str) -> None:
    d = decide(stage, [prior(stage, patch="p0")])
    assert d.reuse is False
    assert d.reason == "patch_changed"
    assert d.outcome is None


@pytest.mark.parametrize("stage", ["ci", "suite"])
def test_checks_stages_are_never_reused_even_for_the_same_patch(stage: str) -> None:
    d = decide(stage, [prior(stage, outcome="green", by=(), digest=None)])
    assert d.reuse is False
    assert d.reason == "checks_never_reused"


def test_checks_are_refused_by_the_stage_in_the_key_not_the_name_asked_for() -> None:
    d = decide("panel", [prior("ci", outcome="green", by=(), digest=None)])
    assert d.reuse is False
    assert d.reason == "checks_never_reused"


def test_a_new_required_reviewer_is_not_reused_away() -> None:
    w = wf(
        lambda d: d["stages"]["panel"].update(
            reviewers=[*PANEL_BY, "test_reviewer"], required=["security_reviewer", "test_reviewer"]
        )
    )
    d = decide("panel", [prior()], graph=w)
    assert d.reuse is False
    assert d.reason == "reviewer_set_changed"


def test_a_new_optional_reviewer_also_re_runs() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(reviewers=[*PANEL_BY, "test_reviewer"]))
    assert decide("panel", [prior()], graph=w).reason == "reviewer_set_changed"


def test_a_dropped_reviewer_re_runs() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(reviewers=["security_reviewer"]))
    assert decide("panel", [prior()], graph=w).reason == "reviewer_set_changed"


def test_reviewer_order_does_not_matter() -> None:
    assert decide("panel", [prior(by=tuple(reversed(PANEL_BY)))]).reuse is True


def test_a_required_reviewer_who_never_ran_is_not_reused() -> None:
    w = wf(
        lambda d: d["stages"]["panel"].update(
            reviewers=["correctness_reviewer"], required=["security_reviewer"]
        )
    )
    d = decide("panel", [prior(by=("correctness_reviewer",), graph=w)], graph=w)
    assert d.reason == "reviewer_set_changed"


def test_a_panel_whose_required_set_is_all_of_its_reviewers_reuses() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(required=list(PANEL_BY)))
    assert decide("panel", [prior(graph=w)], graph=w).reuse is True


# --- (1) only a QA agent is replayed -------------------------------------------------------


@pytest.mark.parametrize("stage", ["triage", "impl"])
def test_an_agent_that_is_not_a_qa_agent_is_never_replayed(stage: str) -> None:
    outcome = "ready"
    by = {"triage": ("triage",), "impl": ("implementer",)}[stage]
    d = decide(stage, [prior(stage, outcome=outcome, by=by)])
    assert d.reuse is False
    assert d.reason == "not_qa_stage"


def test_a_qa_agent_that_could_write_code_is_not_reused() -> None:
    # the stage is a QA stage but its profile can write: stand-in manifest profile
    profiles = {
        **MAN.profiles,
        "qa_agent": MAN.profiles["qa_agent"].model_copy(
            update={"tools": MAN.profiles["qa_agent"].tools | {"workspace.write"}}
        ),
    }
    man = MAN.model_copy(update={"profiles": profiles})
    p = prior("qa")
    d = decide_reuse(W, man, "qa", [p], subject(), PART, prompts=PROMPTS)
    assert d.reuse is False
    assert d.reason == "not_qa_stage"


def test_the_read_only_flag_is_an_extra_condition() -> None:
    d = decide("qa", [prior("qa", read_only=False)])
    assert (d.reuse, d.reason) == (False, "not_read_only")


@pytest.mark.parametrize("flag", [False, 1, None])
def test_read_only_must_be_exactly_true(flag: object) -> None:
    p = dataclasses.replace(prior("qa"), read_only=flag)  # type: ignore[arg-type]
    assert decide("qa", [p]).reason == "not_read_only"


def test_an_agent_that_changed_is_not_reused() -> None:
    w = wf(lambda d: d["stages"]["qa"].update(agent="triage", next={"ready": "ci"}))
    d = decide("qa", [prior("qa")], graph=w)
    assert d.reuse is False
    assert d.reason == "agent_changed"


def test_an_agent_stage_with_an_extra_participant_is_not_reused() -> None:
    d = decide("qa", [prior("qa", by=("qa_agent", "verifier"))])
    assert (d.reuse, d.reason) == (False, "agent_changed")


def test_an_outcome_the_stage_has_no_edge_for_is_re_run() -> None:
    d = decide("qa", [prior("qa", outcome="weird")])
    assert (d.reuse, d.reason) == (False, "outcome_not_reusable")


def test_an_inconclusive_qa_outcome_is_not_reused() -> None:
    d = decide("qa", [prior("qa", outcome="inconclusive")])
    assert (d.reuse, d.reason) == (False, "outcome_not_reusable")


def test_a_degraded_panel_is_re_run() -> None:
    d = decide("panel", [prior(outcome="degraded")])
    assert (d.reuse, d.reason) == (False, "outcome_not_reusable")


# --- (3) QA is bound to the ticket revision ------------------------------------------------


def test_a_qa_result_for_another_ticket_revision_is_not_reused() -> None:
    d = decide("qa", [prior("qa", rev="r0")])
    assert (d.reuse, d.reason) == (False, "ticket_changed")


def test_a_qa_result_with_no_recorded_ticket_revision_is_not_reused() -> None:
    d = decide("qa", [prior("qa", rev=None)])
    assert (d.reuse, d.reason) == (False, "ticket_changed")


def test_a_panel_does_not_need_a_ticket_revision() -> None:
    assert decide("panel", [prior(rev=None)]).reuse is True


# --- (2) the result is bound to the config that produced it --------------------------------


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["stages"]["panel"].update(block_on="low"),
        lambda d: d["stages"]["panel"].update(fail_closed=True),
        lambda d: d["stages"]["panel"].update(required=list(PANEL_BY)),
    ],
    ids=["block_on", "fail_closed", "required"],
)
def test_a_changed_panel_config_re_runs(change: Callable[[dict[str, Any]], None]) -> None:
    d = decide("panel", [prior()], graph=wf(change))
    assert (d.reuse, d.reason) == (False, "config_changed")


def test_a_changed_model_tier_re_runs() -> None:
    w = wf(lambda d: d["stages"]["qa"].update(model_tier="deep"))
    d = decide("qa", [prior("qa")], graph=w)
    assert (d.reuse, d.reason) == (False, "config_changed")


def test_a_changed_profile_re_runs() -> None:
    profiles = {
        **MAN.profiles,
        "qa_agent": MAN.profiles["qa_agent"].model_copy(update={"default_tier": "deep"}),
    }
    man = MAN.model_copy(update={"profiles": profiles})
    d = decide_reuse(W, man, "qa", [prior("qa")], subject(), PART, prompts=PROMPTS)
    assert (d.reuse, d.reason) == (False, "config_changed")


def test_a_result_with_no_config_digest_is_not_reused() -> None:
    for digest in (None, "", "  "):
        d = decide("panel", [prior(digest=digest)])
        assert (d.reuse, d.reason) == (False, "config_digest_missing")


def test_the_digest_is_stable_and_none_for_other_kinds() -> None:
    assert stage_digest(W, MAN, "panel", PROMPTS) == stage_digest(wf(), MAN, "panel", PROMPTS)
    assert stage_digest(W, MAN, "panel", PROMPTS) != stage_digest(W, MAN, "qa", PROMPTS)
    assert stage_digest(W, MAN, "ci", PROMPTS) is None
    assert stage_digest(W, MAN, "nope", PROMPTS) is None


def test_an_unknown_profile_is_not_bound_or_reused() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(reviewers=["ghost"], required=["ghost"]))
    assert stage_digest(w, MAN, "panel", PROMPTS) is None
    d = decide("panel", [prior(by=("ghost",), digest="x")], graph=w)
    assert (d.reuse, d.reason) == (False, "unknown_profile")
    w2 = wf(lambda d: d["stages"]["qa"].update(agent="ghost"))
    assert stage_digest(w2, MAN, "qa", PROMPTS) is None


# --- (5) the run partition -----------------------------------------------------------------


def test_a_result_from_another_run_is_not_reused() -> None:
    d = decide("panel", [prior(partition="TEAM#t1#RUN#r2")])
    assert (d.reuse, d.reason) == (False, "other_run")


def test_a_result_with_no_partition_is_not_reused() -> None:
    assert decide("panel", [prior(partition=None)]).reason == "other_run"


@pytest.mark.parametrize("expected", ["", "  "])
def test_no_expected_partition_means_no_reuse(expected: str) -> None:
    assert decide("panel", [prior(partition=expected)], partition=expected).reason == "other_run"


# --- keys, ordering, shape -----------------------------------------------------------------


def test_a_key_for_another_review_stage_is_not_reused_here() -> None:
    d = decide("qa", [prior("panel")])
    assert (d.reuse, d.reason) == (False, "stage_mismatch")


def test_a_stage_the_workflow_does_not_have_is_refused() -> None:
    d = decide("gone", [prior("gone", by=(), digest=None)])
    assert (d.reuse, d.reason) == (False, "unknown_stage")


def test_a_stage_kind_that_cannot_be_reused_is_refused() -> None:
    d = decide("done", [prior("done", by=(), digest=None)])
    assert (d.reuse, d.reason) == (False, "kind_not_reusable")


@pytest.mark.parametrize("validity", [Validity.EXACT_SHA, Validity.CONTAINS_SHA])
def test_only_same_patch_evidence_is_reusable(validity: Validity) -> None:
    d = decide("panel", [prior(validity=validity, tested=NEW)])
    assert (d.reuse, d.reason) == (False, "validity_not_same_patch")


def test_no_prior_result_runs() -> None:
    assert decide("panel", []).reason == "no_prior_result"


def test_no_subject_runs() -> None:
    d = decide_reuse(W, MAN, "panel", [prior()], None, PART, prompts=PROMPTS)
    assert (d.reuse, d.reason) == (False, "no_subject")


def test_a_pre_push_subject_still_decides_on_patch() -> None:
    pre = Subject(patch_id="p1", ticket_revision="r1", base_sha=NEW)
    assert decide("panel", [prior()], pre).reuse is True
    pre2 = Subject(patch_id="p2", ticket_revision="r1", base_sha=NEW)
    assert decide("panel", [prior()], pre2).reason == "patch_changed"


def test_a_prior_without_evidence_runs() -> None:
    bad = dataclasses.replace(prior(), evidence=None)  # type: ignore[arg-type]
    assert decide("panel", [bad]).reason == "no_evidence"


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
        "EV#Panel#" + U1,  # not an identifier
        "EV#1panel#" + U1,
        "EV#pa nel#" + U1,
        "EV#panel#" + U1.lower(),  # lower case
        "EV#panel#" + U1 + "0",  # one too long
        "EV#panel#" + U1[:-1],  # one too short
        "EV#panel#" + "8" + U1[1:],  # time part beyond 2^48
        "EV#panel#" + U1[:-1] + "I",  # not in the Crockford alphabet
        "EV#panel#" + U1[:-1] + "L",
        "EV#panel#" + U1[:-1] + "O",
        "EV#panel#" + U1[:-1] + "U",
        "EV#panel#" + U1[:-1] + "-",
    ],
)
def test_a_malformed_key_runs(key: str) -> None:
    bad = dataclasses.replace(prior(), key=key)
    d = decide("panel", [bad])
    assert (d.reuse, d.reason) == (False, "bad_key")


@pytest.mark.parametrize("ulid", ["0" * 26, "7" + "Z" * 25, "01ARZ3NDEKTSV4RRFFQ69G5FAV"])
def test_a_well_formed_ulid_parses(ulid: str) -> None:
    assert parse_evidence_key(f"EV#panel#{ulid}") == ("panel", ulid)


def test_parse_evidence_key_rejects_non_strings() -> None:
    assert parse_evidence_key("EV#panel") is None
    assert parse_evidence_key(None) is None
    assert parse_evidence_key(b"EV#panel#" + U1.encode()) is None


def test_a_duck_typed_candidate_is_refused() -> None:
    class Quack:
        key = f"EV#panel#{U1}"
        evidence = Evidence(OLD, "p1", Validity.SAME_PATCH)
        outcome = "clean"
        participants = PANEL_BY
        read_only = True

    d = decide("panel", [Quack()])  # type: ignore[list-item]
    assert (d.reuse, d.reason) == (False, "bad_key")
    assert decide("panel", [object()]).reuse is False  # type: ignore[list-item]


@pytest.mark.parametrize(
    "bad",
    [
        {"outcome": None},
        {"participants": ["security_reviewer"]},
        {"participants": ("security_reviewer", 7)},
        {"participants": ("security_reviewer", " ")},
    ],
)
def test_a_malformed_record_runs(bad: dict[str, Any]) -> None:
    d = decide("panel", [dataclasses.replace(prior(), **bad)])
    assert (d.reuse, d.reason) == (False, "bad_record")


def test_the_latest_result_decides_and_an_older_one_is_not_a_fallback() -> None:
    older = prior(ulid=U1)
    newer = prior(ulid=U2, patch="p0")  # latest saw a different patch
    assert decide("panel", [older, newer]).reason == "patch_changed"
    assert decide("panel", [newer, older]).reason == "patch_changed"  # input order is irrelevant


def test_a_tie_for_the_newest_result_is_ambiguous() -> None:
    a = prior(ulid=U2)
    b = prior(ulid=U2, tested=NEW)
    assert decide("panel", [a, b]).reason == "ambiguous"
    # a tie below the newest does not matter
    assert decide("panel", [prior(ulid=U1), prior(ulid=U1, tested=NEW), a]).reuse is True


def test_results_of_other_stages_do_not_hide_this_stages_result() -> None:
    other = prior("qa", ulid=U2)
    d = decide("panel", [prior(ulid=U1), other])
    assert d.reuse is True
    assert d.key == f"EV#panel#{U1}"


def test_the_decision_is_recorded_as_plain_data() -> None:
    d = decide("panel", [prior()])
    assert d.to_data() == {
        "stage": "panel",
        "reuse": True,
        "reason": "same_patch",
        "evidence": f"EV#panel#{U1}",
        "outcome": "clean",
        "notes": [f"{OLDER_BASE_NOTE} ({OLD})"],
    }
    r = decide("panel", [])
    assert r.to_data() == {
        "stage": "panel",
        "reuse": False,
        "reason": "no_prior_result",
        "evidence": None,
        "outcome": None,
        "notes": [],
    }
    json.dumps(d.to_data())


def test_decision_and_record_types_are_frozen() -> None:
    d = decide("panel", [])
    with pytest.raises(AttributeError):
        d.reuse = True  # type: ignore[misc]
    with pytest.raises(AttributeError):
        prior().outcome = "findings"  # type: ignore[misc]


# --- D2-38: reuse hardening ----------------------------------------------------------------


def test_a_panel_prior_listing_a_participant_twice_is_refused() -> None:
    # same set as today's reviewers, but one listed twice: a frozenset comparison would pass it
    d = decide("panel", [prior(by=(*PANEL_BY, "security_reviewer"))])
    assert (d.reuse, d.reason) == (False, "reviewer_set_changed")


def test_a_panel_prior_repeating_one_reviewer_for_two_is_refused() -> None:
    d = decide("panel", [prior(by=("security_reviewer", "security_reviewer"))])
    assert (d.reuse, d.reason) == (False, "reviewer_set_changed")


def test_a_qa_prior_listing_the_agent_twice_is_refused() -> None:
    d = decide("qa", [prior("qa", by=("qa_agent", "qa_agent"))])
    assert (d.reuse, d.reason) == (False, "agent_changed")


def _with_prompt(name: str, **change: str) -> dict[str, PromptTemplate]:
    old = PROMPTS[name]
    new = PromptTemplate(
        name=old.name,
        version=change.get("version", old.version),
        text=change.get("text", old.text),
    )
    return {**PROMPTS, name: new}


@pytest.mark.parametrize(
    ("stage", "name"),
    [("panel", "security_reviewer"), ("panel", "correctness_reviewer"), ("qa", "qa_agent")],
)
@pytest.mark.parametrize("change", [{"version": "2"}, {"text": "You are different."}])
def test_a_prompt_change_invalidates_reuse(stage: str, name: str, change: dict[str, str]) -> None:
    p = prior(stage)
    assert stage_digest(W, MAN, stage, PROMPTS) != stage_digest(
        W, MAN, stage, _with_prompt(name, **change)
    )
    d = decide_reuse(W, MAN, stage, [p], subject(), PART, prompts=_with_prompt(name, **change))
    assert (d.reuse, d.reason) == (False, "config_changed")


@pytest.mark.parametrize("stage", ["panel", "qa"])
def test_a_missing_prompt_is_not_bound_and_re_runs(stage: str) -> None:
    assert stage_digest(W, MAN, stage) is None
    assert stage_digest(W, MAN, stage, {}) is None
    d = decide_reuse(W, MAN, stage, [prior(stage)], subject(), PART)
    assert (d.reuse, d.reason) == (False, "prompt_missing")
    some = {k: v for k, v in PROMPTS.items() if k != "security_reviewer"}
    d = decide_reuse(W, MAN, "panel", [prior()], subject(), PART, prompts=some)
    assert (d.reuse, d.reason) == (False, "prompt_missing")


def test_a_prompt_of_the_wrong_type_or_name_is_not_bound() -> None:
    assert stage_digest(W, MAN, "qa", {**PROMPTS, "qa_agent": "text"}) is None  # type: ignore[dict-item]
    other = PromptTemplate(name="triage", version="1", text="x")
    assert stage_digest(W, MAN, "qa", {**PROMPTS, "qa_agent": other}) is None


def test_a_profile_outcome_change_invalidates_reuse() -> None:
    qa = MAN.profiles["qa_agent"]
    profiles = {**MAN.profiles, "qa_agent": qa.model_copy(update={"outcomes": qa.outcomes | {"x"}})}
    man = MAN.model_copy(update={"profiles": profiles})
    assert stage_digest(W, man, "qa", PROMPTS) != stage_digest(W, MAN, "qa", PROMPTS)
    d = decide_reuse(W, man, "qa", [prior("qa")], subject(), PART, prompts=PROMPTS)
    assert (d.reuse, d.reason) == (False, "config_changed")
