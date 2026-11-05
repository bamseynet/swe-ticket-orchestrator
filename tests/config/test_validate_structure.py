"""D2-03: the structural validator (V1, V2, V3, V7, V8, V9, V10, V13, V15).

Every rule has a positive fixture (the base workflow passes) and a negative one (one change makes
exactly that rule fail, and the message names the stage and says how to fix it). Fixtures are
synthetic.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from typing import Any

import pytest
import yaml

from sto.config.manifest import Manifest, load_manifest
from sto.config.org_policy import check_org_required_gates
from sto.config.schema import (
    Issue,
    OrgPolicy,
    SchemaError,
    TeamConfig,
    Workflow,
    load_document,
)
from sto.config.validate_structure import (
    check_budget_ceilings,
    check_route_orders,
    validate_structure,
)

MANIFEST = load_manifest()


def _dump(data: dict[str, Any]) -> str:
    return yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False)


def _gate(gtype: str, roles: list[str], nxt: dict[str, Any], **extra: Any) -> dict[str, Any]:
    gate = {
        "type": gtype,
        "eligible_roles": roles,
        "decisions": ["approve", "request_changes", "reject"],
        "decision_surfaces": ["ui"],
        **extra,
    }
    return {"kind": "gate", "gate": gate, "next": nxt}


WF_DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "Workflow",
    "metadata": {"name": "ledger-flow", "team": "ledger"},
    "limits": {
        "loops": {"fix_loop": 3, "review_loop": 3, "info_loop": 3},
        "max_steps_per_run": 100,
        "max_run_age": "30d",
    },
    "start": "triage",
    "stages": {
        "triage": {
            "kind": "agent",
            "agent": "triage",
            "next": {"ready": "implement", "needs_info": "ask", "not_actionable": "closed"},
        },
        "ask": {
            "kind": "wait",
            "wait_for": "human_answer",
            "timeout": "2d",
            "next": {"resumed": {"to": "triage", "loop": "info_loop"}, "timeout": "closed"},
        },
        "implement": {
            "kind": "agent",
            "agent": "implementer",
            "next": {"ready": "panel", "blocked": "closed"},
        },
        "panel": {
            "kind": "review_panel",
            "reviewers": ["correctness_reviewer"],
            "required": ["correctness_reviewer"],
            "block_on": "high",
            "next": {
                "clean": "review_gate",
                "findings": {"to": "implement", "loop": "fix_loop"},
                "degraded": "review_gate",
            },
        },
        "review_gate": _gate(
            "review",
            ["reviewer"],
            {
                "approved": "merge",
                "changes_requested": {"to": "implement", "loop": "review_loop"},
                "rejected": "rejected_end",
            },
        ),
        "merge": {
            "kind": "effect",
            "effect": "pr.merge",
            "requires_gates": ["review_gate"],
            "next": {
                "done": "qa_gate",
                "conflict": {"to": "implement", "loop": "fix_loop"},
                "stale": {"to": "implement", "loop": "fix_loop"},
            },
        },
        "qa_gate": _gate(
            "qa",
            ["qa"],
            {
                "approved": "done",
                "changes_requested": {"to": "implement", "loop": "review_loop"},
                "rejected": "rejected_end",
            },
        ),
        "done": {"kind": "terminal", "result": "done"},
        "closed": {"kind": "terminal", "result": "closed"},
        "rejected_end": {"kind": "terminal", "result": "rejected"},
    },
}

ORG_DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "OrgPolicy",
    "floors": {
        "mandatory_gate_roles": {
            "pre_push": ["reviewer"],
            "review": ["reviewer"],
            "qa": ["qa", "reviewer"],
        },
        "decision_surfaces": {"review": ["ui", "slack", "github"], "qa": ["ui", "slack"]},
        "hold_after_approval_min": "10m",
        "identity_max_age": "8h",
    },
    "ceilings": {
        "max_steps_per_run": 200,
        "max_run_age": "60d",
        "max_loop": 5,
        "max_stage_duration": "14d",
        "max_run_usd": 50,
    },
    "route_orders": {"risk": ["low", "medium", "high"]},
}


def _wf(mutate: Callable[[dict[str, Any]], None] | None = None) -> Workflow:
    data = copy.deepcopy(WF_DOC)
    if mutate:
        mutate(data)
    wf = load_document(_dump(data))
    assert isinstance(wf, Workflow)
    return wf


def _org(mutate: Callable[[dict[str, Any]], None] | None = None) -> OrgPolicy:
    data = copy.deepcopy(ORG_DOC)
    if mutate:
        mutate(data)
    pol = load_document(_dump(data))
    assert isinstance(pol, OrgPolicy)
    return pol


def _issues(
    mutate: Callable[[dict[str, Any]], None] | None = None,
    *,
    org: Callable[[dict[str, Any]], None] | None = None,
    manifest: Manifest = MANIFEST,
) -> list[Issue]:
    return validate_structure(_wf(mutate), manifest=manifest, policy=_org(org))


def _text(issues: list[Issue]) -> str:
    return "\n".join(str(i) for i in issues)


def _stages(change: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
    return lambda d: change(d["stages"])


def _refused(
    mutate: Callable[[dict[str, Any]], None] | None = None,
    *,
    org: Callable[[dict[str, Any]], None] | None = None,
    names: str,
    says: str,
) -> list[Issue]:
    """The change is refused, and a message names ``names`` and contains ``says``."""
    issues = _issues(mutate, org=org)
    assert issues, "expected a refusal"
    hits = [i for i in issues if names in i.path + i.message and says in i.message]
    assert hits, _text(issues)
    return issues


# --- the positive fixture ------------------------------------------------------------------


def test_the_base_workflow_passes_every_rule() -> None:
    assert _issues() == []


def test_the_base_workflow_also_meets_the_v17_org_requirements() -> None:
    assert check_org_required_gates(_wf(), _org(), team="ledger") == []


# --- V1 references, reachability -----------------------------------------------------------


def test_v1_an_edge_to_an_unknown_stage_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["triage"]["next"]["ready"] = "implemnt"

    _refused(_stages(change), names="triage", says="implemnt")


def test_v1_an_unknown_start_is_refused() -> None:
    _refused(lambda d: d.__setitem__("start", "nowhere"), names="start", says="nowhere")


def test_v1_an_unknown_on_external_commit_is_refused() -> None:
    _refused(
        lambda d: d.__setitem__("on_external_commit", "nowhere"),
        names="on_external_commit",
        says="nowhere",
    )


def test_v1_requires_gates_must_name_a_gate_stage() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["requires_gates"] = ["panel"]

    _refused(_stages(change), names="merge", says="panel is not a gate")


def test_v1_requires_gates_unknown_name_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["requires_gates"] = ["review_gate", "ghost"]

    _refused(_stages(change), names="merge", says="ghost")


def test_v1_definition_of_done_must_name_a_stage() -> None:
    _refused(
        lambda d: d.__setitem__("definition_of_done", [{"stage": "ghost", "check": "ac_present"}]),
        names="definition_of_done",
        says="ghost",
    )


def test_v1_an_unreachable_stage_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["island"] = {"kind": "terminal", "result": "closed"}

    _refused(_stages(change), names="island", says="unreachable")


def test_v1_a_stage_reached_only_from_on_external_commit_is_reachable() -> None:
    def change(d: dict[str, Any]) -> None:
        d["on_external_commit"] = "recheck"
        d["stages"]["recheck"] = {
            "kind": "checks",
            "source": "ci",
            "required": ["unit"],
            "timeout": "1h",
            "next": {"green": "review_gate", "red": "implement"},
        }

    assert _issues(change) == []


def test_v1_a_stage_with_no_path_to_a_terminal_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["ask"]["next"] = {"resumed": "ask2", "timeout": "ask2"}
        s["ask2"] = {
            "kind": "wait",
            "wait_for": "human_answer",
            "timeout": "1d",
            "next": {"resumed": "ask", "timeout": "ask"},
        }

    issues = _issues(_stages(change))
    assert any("ask" in i.path and "no path to a terminal" in i.message for i in issues), _text(
        issues
    )


# --- V2 outcomes ---------------------------------------------------------------------------


def test_v2_an_agent_stage_needs_an_edge_for_each_profile_outcome() -> None:
    def change(s: dict[str, Any]) -> None:
        del s["triage"]["next"]["not_actionable"]

    _refused(_stages(change), names="triage", says="not_actionable")


def test_v2_an_agent_edge_the_profile_cannot_produce_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["triage"]["next"]["maybe"] = "closed"

    _refused(_stages(change), names="triage", says="maybe")


def test_v2_an_unknown_agent_profile_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["triage"]["agent"] = "wizard"

    _refused(_stages(change), names="triage", says="wizard")


def test_v2_a_worker_profile_cannot_run_a_stage() -> None:
    def change(s: dict[str, Any]) -> None:
        s["triage"]["agent"] = "coder"

    _refused(_stages(change), names="triage", says="worker")


def test_v2_a_gate_needs_approved_changes_requested_and_rejected() -> None:
    def change(s: dict[str, Any]) -> None:
        del s["review_gate"]["next"]["changes_requested"]

    _refused(_stages(change), names="review_gate", says="changes_requested")


def test_v2_a_gate_needs_a_retest_edge_only_when_it_allows_retest() -> None:
    def allow(s: dict[str, Any]) -> None:
        s["qa_gate"]["gate"]["decisions"].append("retest")

    _refused(_stages(allow), names="qa_gate", says="retest")

    def both(s: dict[str, Any]) -> None:
        allow(s)
        s["qa_gate"]["next"]["retest"] = {"to": "qa_gate", "loop": "review_loop"}

    assert _issues(_stages(both)) == []


def test_v2_a_gate_with_expire_after_needs_an_expired_edge() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["timeouts"] = {"expire_after": "3d"}

    _refused(_stages(change), names="review_gate", says="expired")


def test_v2_an_expired_edge_without_expire_after_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["next"]["expired"] = "closed"

    _refused(_stages(change), names="review_gate", says="expired")


def test_v2_an_effect_needs_an_edge_for_each_catalog_outcome() -> None:
    def change(s: dict[str, Any]) -> None:
        del s["merge"]["next"]["stale"]

    _refused(_stages(change), names="merge", says="stale")


def test_v2_a_checks_stage_needs_green_and_red() -> None:
    def change(s: dict[str, Any]) -> None:
        s["ci"] = {
            "kind": "checks",
            "source": "ci",
            "required": ["unit"],
            "timeout": "1h",
            "next": {"green": "review_gate", "red": "implement"},
        }
        s["panel"]["next"]["clean"] = "ci"
        del s["ci"]["next"]["red"]

    _refused(_stages(change), names="ci", says="red")


def test_v2_a_panel_needs_clean_findings_and_degraded() -> None:
    def change(s: dict[str, Any]) -> None:
        del s["panel"]["next"]["degraded"]

    _refused(_stages(change), names="panel", says="degraded")


def test_v2_a_wait_needs_resumed_and_timeout() -> None:
    def change(s: dict[str, Any]) -> None:
        del s["ask"]["next"]["timeout"]

    _refused(_stages(change), names="ask", says="timeout")


def test_v2_a_route_needs_a_default() -> None:
    def change(s: dict[str, Any]) -> None:
        s["by_risk"] = {
            "kind": "route",
            "field": "risk",
            "order": ["low", "medium", "high"],
            "next": {"high": "review_gate"},
        }
        s["panel"]["next"]["clean"] = "by_risk"

    _refused(_stages(change), names="by_risk", says="default")


def test_v2_a_route_edge_outside_its_order_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["by_risk"] = {
            "kind": "route",
            "field": "risk",
            "order": ["low", "medium", "high"],
            "next": {"critical": "review_gate", "default": "review_gate"},
        }
        s["panel"]["next"]["clean"] = "by_risk"

    _refused(_stages(change), names="by_risk", says="critical")


# --- V3 capped cycles ----------------------------------------------------------------------


def test_v3_an_uncapped_cycle_is_refused_and_printed() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["next"]["conflict"] = "implement"
        s["merge"]["next"]["stale"] = "implement"
        s["panel"]["next"]["findings"] = "implement"
        s["review_gate"]["next"]["changes_requested"] = "implement"
        s["qa_gate"]["next"]["changes_requested"] = "implement"

    issues = _issues(_stages(change))
    cycle = [i for i in issues if "cycle" in i.message]
    assert cycle, _text(issues)
    msg = cycle[0].message
    assert "implement -> panel -> implement" in msg or "implement -> panel -> review_gate" in msg
    assert "loop" in msg  # says how to fix it


def test_v3_one_uncapped_edge_in_a_capped_graph_is_found() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["next"]["stale"] = "implement"

    _refused(_stages(change), names="merge", says="cycle")


def test_v3_a_self_loop_without_a_cap_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["ask"]["next"]["resumed"] = "ask"

    _refused(_stages(change), names="ask", says="cycle")


def test_v3_a_loop_name_must_have_a_limit() -> None:
    def change(s: dict[str, Any]) -> None:
        s["panel"]["next"]["findings"] = {"to": "implement", "loop": "mystery"}

    issues = _refused(_stages(change), names="panel", says="mystery")
    # and a loop with no limit caps nothing, so the cycle it was meant to cap is reported too
    assert any("cycle" in i.message for i in issues), _text(issues)


def test_v3_a_loop_limit_may_not_pass_the_platform_cap() -> None:
    def change(d: dict[str, Any]) -> None:
        d["limits"]["loops"]["fix_loop"] = 501

    _refused(change, names="fix_loop", says="platform")


def test_v3_a_loop_limit_may_not_pass_the_org_ceiling() -> None:
    def change(d: dict[str, Any]) -> None:
        d["limits"]["loops"]["fix_loop"] = 6

    _refused(change, names="fix_loop", says="org")


# --- V7 a human-only path ------------------------------------------------------------------


def test_v7_empty_eligible_roles_are_refused_by_the_schema() -> None:
    def change(d: dict[str, Any]) -> None:
        d["stages"]["review_gate"]["gate"]["eligible_roles"] = []

    with pytest.raises(SchemaError):
        _wf(change)


def test_v7_the_validator_also_refuses_an_empty_roles_list_that_got_past_the_schema() -> None:
    wf = _wf()
    gate = wf.stages["review_gate"].gate  # type: ignore[union-attr]
    bad_gate = gate.model_copy(update={"eligible_roles": ()})
    stages = dict(wf.stages)
    stages["review_gate"] = wf.stages["review_gate"].model_copy(update={"gate": bad_gate})
    bad = wf.model_copy(update={"stages": stages})
    issues = validate_structure(bad, manifest=MANIFEST, policy=_org())
    assert any("review_gate" in i.path and "eligible_roles" in i.message for i in issues)


def _custom_gate(s: dict[str, Any], **gate: Any) -> None:
    """A custom gate between review and merge: no mandatory-role rule applies to it."""
    s["sec"] = _gate(
        "custom",
        ["security_officer"],
        {
            "approved": "merge",
            "changes_requested": {"to": "implement", "loop": "review_loop"},
            "rejected": "closed",
        },
        **gate,
    )
    s["review_gate"]["next"]["approved"] = "sec"


def _custom_surfaces(d: dict[str, Any]) -> None:
    d["floors"]["decision_surfaces"]["custom"] = ["ui"]


def test_v7_a_quorum_role_must_be_eligible() -> None:
    # a custom gate, so V15's mandatory-role check cannot be what refuses it
    def change(s: dict[str, Any]) -> None:
        _custom_gate(s, quorum=[{"role": "intern", "count": 1}])

    assert _issues(_stages(lambda s: _custom_gate(s)), org=_custom_surfaces) == []
    issues = _issues(_stages(change), org=_custom_surfaces)
    assert [i for i in issues if "not in eligible_roles" in i.message and "intern" in i.message]
    assert not [i for i in issues if "may not decide" in i.message]


def test_v7_a_quorum_count_below_one_is_refused_by_the_validator_too() -> None:
    wf = _wf(
        _stages(
            lambda s: s["review_gate"]["gate"].__setitem__(
                "quorum", [{"role": "reviewer", "count": 1}]
            )
        )
    )
    stage = wf.stages["review_gate"]
    gate = stage.gate  # type: ignore[union-attr]
    assert gate.quorum is not None
    entry = gate.quorum[0].model_copy(update={"count": 0})
    bad_gate = gate.model_copy(update={"quorum": (entry,)})
    stages = {**wf.stages, "review_gate": stage.model_copy(update={"gate": bad_gate})}
    issues = validate_structure(
        wf.model_copy(update={"stages": stages}), manifest=MANIFEST, policy=_org()
    )
    assert any("count" in i.message and "review_gate" in i.path for i in issues), _text(issues)


def test_v15_a_quorum_role_the_org_does_not_give_a_mandatory_gate_is_refused() -> None:
    # past the schema and V7, so only V15's quorum check can name the role
    wf = _wf()
    stage = wf.stages["review_gate"]
    gate = stage.gate  # type: ignore[union-attr]
    from sto.config.schema import Quorum

    bad_gate = gate.model_copy(update={"quorum": (Quorum(role="intern", count=1),)})
    stages = {**wf.stages, "review_gate": stage.model_copy(update={"gate": bad_gate})}
    issues = validate_structure(
        wf.model_copy(update={"stages": stages}), manifest=MANIFEST, policy=_org()
    )
    assert any("intern may not decide a review gate" in i.message for i in issues), _text(issues)


def test_v7_duplicate_quorum_roles_are_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["quorum"] = [
            {"role": "reviewer", "count": 1},
            {"role": "reviewer", "count": 1},
        ]

    _refused(_stages(change), names="review_gate", says="twice")


def test_v7_a_quorum_of_zero_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["quorum"] = [{"role": "reviewer", "count": 0}]

    with pytest.raises(SchemaError):
        _wf(_stages(change))


def test_v7_auto_approve_on_a_gate_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["auto_approve"] = True

    with pytest.raises(SchemaError):
        _wf(_stages(change))


def test_v7_a_gate_with_a_valid_quorum_passes() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["quorum"] = [{"role": "reviewer", "count": 2}]

    assert _issues(_stages(change)) == []


# --- V8 non-approval stays non-approval ----------------------------------------------------


def test_v8_a_rejected_edge_cannot_lead_to_a_gated_effect() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["next"]["rejected"] = "merge"

    _refused(_stages(change), names="review_gate", says="merge")


def test_v8_an_expired_edge_cannot_lead_to_a_gated_effect() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["timeouts"] = {"expire_after": "3d"}
        s["review_gate"]["next"]["expired"] = "merge"

    _refused(_stages(change), names="review_gate", says="expired")


def test_v8_a_gated_effect_further_down_the_path_is_found_and_the_path_is_printed() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["next"]["rejected"] = "ask"
        s["ask"]["next"]["resumed"] = "merge"

    issues = _refused(_stages(change), names="review_gate", says="ask -> merge")
    assert issues


def test_v8_a_rejected_edge_that_goes_back_through_a_gate_approval_is_fine() -> None:
    def change(s: dict[str, Any]) -> None:
        s["qa_gate"]["next"]["rejected"] = {"to": "review_gate", "loop": "review_loop"}

    assert _issues(_stages(change)) == []


def test_v8_a_rejected_edge_to_a_terminal_passes() -> None:
    assert _issues() == []


# --- V9 budgets and limits within org ceilings; durations ----------------------------------


def test_v9_max_steps_above_the_org_ceiling_is_refused() -> None:
    _refused(
        lambda d: d["limits"].__setitem__("max_steps_per_run", 201),
        names="max_steps_per_run",
        says="org ceiling",
    )


def test_v9_max_run_age_above_the_org_ceiling_is_refused() -> None:
    _refused(
        lambda d: d["limits"].__setitem__("max_run_age", "61d"),
        names="max_run_age",
        says="org ceiling",
    )


def test_v9_limits_at_the_ceiling_pass() -> None:
    def change(d: dict[str, Any]) -> None:
        d["limits"].update(max_steps_per_run=200, max_run_age="60d")
        d["limits"]["loops"]["fix_loop"] = 5

    assert _issues(change) == []


def test_v9_without_ceilings_the_platform_caps_still_hold() -> None:
    def org(d: dict[str, Any]) -> None:
        del d["ceilings"]

    assert _issues(org=org) == []
    wf = _wf()
    limits = wf.limits.model_copy(update={"max_steps_per_run": 501})
    bad = wf.model_copy(update={"limits": limits})
    issues = validate_structure(bad, manifest=MANIFEST, policy=_org(org))
    assert any("max_steps_per_run" in i.path and "platform" in i.message for i in issues)


def test_v9_a_wait_longer_than_the_run_is_refused() -> None:
    def change(d: dict[str, Any]) -> None:
        d["limits"]["max_run_age"] = "1d"
        d["stages"]["ask"]["timeout"] = "2d"

    _refused(change, names="ask", says="max_run_age")


def test_v9_a_stage_duration_above_the_org_ceiling_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["ask"]["timeout"] = "15d"

    _refused(_stages(change), names="ask", says="org ceiling")


@pytest.mark.parametrize("key", ["remind_after", "escalate_after", "expire_after"])
def test_v9_every_gate_timeout_has_an_upper_bound(key: str) -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["timeouts"] = {key: "15d"}
        if key == "expire_after":
            s["review_gate"]["next"]["expired"] = "closed"
        if key == "escalate_after":
            s["review_gate"]["gate"]["timeouts"]["escalate_to"] = "reviewer"

    _refused(_stages(change), names="review_gate", says=key)


def test_v9_a_checks_timeout_has_an_upper_bound() -> None:
    def change(s: dict[str, Any]) -> None:
        s["ci"] = {
            "kind": "checks",
            "source": "ci",
            "required": ["unit"],
            "timeout": "30d",
            "next": {"green": "review_gate", "red": "implement"},
        }
        s["panel"]["next"]["clean"] = "ci"

    _refused(_stages(change), names="ci", says="timeout")


def test_v9_weeks_are_counted_as_seven_days() -> None:
    def change(s: dict[str, Any]) -> None:
        s["ask"]["timeout"] = "3w"

    _refused(_stages(change), names="ask", says="org ceiling")


def test_v9_budget_above_the_org_ceiling_is_refused() -> None:
    def team(run_usd: float) -> TeamConfig:
        doc = {
            "apiVersion": "sto/v1",
            "kind": "TeamConfig",
            "metadata": {"team": "ledger"},
            "budgets": {"run_usd": run_usd, "team_monthly_usd": 500},
        }
        cfg = load_document(_dump(doc))
        assert isinstance(cfg, TeamConfig)
        return cfg

    assert check_budget_ceilings(team(50), _org()) == []
    issues = check_budget_ceilings(team(51), _org())
    assert issues
    assert "run_usd" in _text(issues)
    assert "org ceiling" in _text(issues)


def test_v9_the_org_document_refuses_a_ceiling_of_zero() -> None:
    with pytest.raises(SchemaError):
        _org(lambda d: d["ceilings"].__setitem__("max_loop", 0))


# --- V10 decision surfaces, waive ----------------------------------------------------------


def test_v10_a_surface_the_org_does_not_permit_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["qa_gate"]["gate"]["decision_surfaces"] = ["ui", "slack", "github"]

    _refused(_stages(change), names="qa_gate", says="github")


def test_v10_a_gate_type_missing_from_the_org_surfaces_permits_nothing() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["type"] = "custom"

    _refused(_stages(change), names="review_gate", says="custom")


def test_v10_github_is_only_for_review_type_gates_even_if_the_org_lists_it() -> None:
    # the org document itself refuses github on qa
    with pytest.raises(SchemaError) as err:
        _org(lambda d: d["floors"]["decision_surfaces"].__setitem__("qa", ["ui", "github"]))
    assert "github" in str(err.value)


def test_v10_github_on_a_review_gate_passes_when_the_org_permits_it() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["decision_surfaces"] = ["ui", "github"]

    assert _issues(_stages(change)) == []


def test_v10_github_is_refused_on_a_review_gate_if_the_org_does_not_permit_it() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["decision_surfaces"] = ["ui", "github"]

    def org(d: dict[str, Any]) -> None:
        d["floors"]["decision_surfaces"]["review"] = ["ui", "slack"]

    _refused(_stages(change), org=org, names="review_gate", says="github")


def test_v10_waive_needs_the_org_to_allow_it() -> None:
    def change(s: dict[str, Any]) -> None:
        s["qa_gate"]["gate"]["decisions"].append("waive")

    _refused(_stages(change), names="qa_gate", says="waive")

    def allow(d: dict[str, Any]) -> None:
        d["floors"]["waive_allowed"] = True

    assert _issues(_stages(change), org=allow) == []


# --- V13 no empty floors -------------------------------------------------------------------


@pytest.mark.parametrize("field", ["reviewers", "required"])
def test_v13_an_empty_panel_list_is_refused_by_the_schema(field: str) -> None:
    def change(s: dict[str, Any]) -> None:
        s["panel"][field] = []

    with pytest.raises(SchemaError):
        _wf(_stages(change))


@pytest.mark.parametrize("field", ["reviewers", "required"])
def test_v13_the_validator_refuses_an_empty_panel_list_that_got_past_the_schema(
    field: str,
) -> None:
    wf = _wf()
    stages = dict(wf.stages)
    stages["panel"] = wf.stages["panel"].model_copy(update={field: ()})
    issues = validate_structure(
        wf.model_copy(update={"stages": stages}), manifest=MANIFEST, policy=_org()
    )
    assert any("panel" in i.path and f"{field} is empty" in i.message for i in issues), _text(
        issues
    )


def test_v13_a_required_reviewer_must_be_on_the_panel() -> None:
    def change(s: dict[str, Any]) -> None:
        s["panel"]["required"] = ["security_reviewer"]

    _refused(_stages(change), names="panel", says="security_reviewer")


def _with_ci(required: Any) -> dict[str, Any]:
    return {
        "kind": "checks",
        "source": "ci",
        "required": required,
        "timeout": "1h",
        "next": {"green": "review_gate", "red": {"to": "implement", "loop": "fix_loop"}},
    }


def _add_ci(required: Any) -> Callable[[dict[str, Any]], None]:
    def change(s: dict[str, Any]) -> None:
        s["ci"] = _with_ci(required)
        s["panel"]["next"]["clean"] = "ci"

    return _stages(change)


def test_v13_checks_with_no_required_check_are_refused_by_the_schema() -> None:
    with pytest.raises(SchemaError):
        _wf(_add_ci([]))


def test_v13_the_validator_refuses_empty_checks_that_got_past_the_schema() -> None:
    base = _wf(_add_ci(["unit"]))
    stages = dict(base.stages)
    stages["ci"] = base.stages["ci"].model_copy(update={"required": ()})
    bad = base.model_copy(update={"stages": stages})
    issues = validate_structure(bad, manifest=MANIFEST, policy=_org())
    assert any("ci" in i.path and "required" in i.message for i in issues), _text(issues)


def test_v13_team_default_is_allowed_at_publish() -> None:
    def change(s: dict[str, Any]) -> None:
        s["ci"] = {
            "kind": "checks",
            "source": "ci",
            "required": "team_default",
            "timeout": "1h",
            "next": {"green": "review_gate", "red": {"to": "implement", "loop": "fix_loop"}},
        }
        s["panel"]["next"]["clean"] = "ci"

    assert _issues(_stages(change)) == []


# --- V15 mandatory roles, typed with -------------------------------------------------------


def test_v15_a_mandatory_gate_may_only_list_the_orgs_roles() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["eligible_roles"] = ["reviewer", "developer"]

    _refused(_stages(change), names="review_gate", says="developer")


def test_v15_qa_roles_come_from_the_qa_entry() -> None:
    def change(s: dict[str, Any]) -> None:
        s["qa_gate"]["gate"]["eligible_roles"] = ["qa", "reviewer"]

    assert _issues(_stages(change)) == []

    def bad(s: dict[str, Any]) -> None:
        s["qa_gate"]["gate"]["eligible_roles"] = ["qa", "intern"]

    _refused(_stages(bad), names="qa_gate", says="intern")


def test_v15_a_custom_gate_may_list_any_role() -> None:
    def change(s: dict[str, Any]) -> None:
        s["sec"] = _gate(
            "custom",
            ["security_officer"],
            {"approved": "merge", "changes_requested": "implement", "rejected": "closed"},
        )
        s["sec"]["next"]["changes_requested"] = {"to": "implement", "loop": "review_loop"}
        s["review_gate"]["next"]["approved"] = "sec"

    org = lambda d: d["floors"]["decision_surfaces"].__setitem__("custom", ["ui"])  # noqa: E731
    assert _issues(_stages(change), org=org) == []


def test_v15_a_quorum_role_of_a_mandatory_gate_must_be_the_orgs_too() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["eligible_roles"] = ["reviewer"]
        s["review_gate"]["gate"]["quorum"] = [{"role": "reviewer", "count": 1}]

    assert _issues(_stages(change)) == []


def test_v15_an_unknown_with_key_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["with"] = {"method": "squash", "flavour": "x"}

    _refused(_stages(change), names="merge", says="flavour")


def test_v15_auto_approve_on_pr_merge_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["with"] = {"auto_approve": True}

    _refused(_stages(change), names="merge", says="auto_approve")


@pytest.mark.parametrize("key", ["AUTO_APPROVE", "Auto_Approve", "auto_approve", "approve"])
def test_v15_the_approval_hint_is_given_whatever_the_case(key: str) -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["with"] = {key: True}

    issues = _refused(_stages(change), names="merge", says=key)
    assert any("requires_gates" in i.message for i in issues), _text(issues)


def test_v15_a_with_value_outside_the_enum_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["with"] = {"method": "fast_forward"}

    _refused(_stages(change), names="merge", says="fast_forward")


def test_v15_a_valid_with_passes() -> None:
    def change(s: dict[str, Any]) -> None:
        s["merge"]["with"] = {"method": "squash"}

    assert _issues(_stages(change)) == []


def test_v15_a_required_with_key_must_be_present() -> None:
    def change(s: dict[str, Any]) -> None:
        s["note"] = {
            "kind": "effect",
            "effect": "ticket.transition",
            "requires_gates": ["qa_gate"],
            "next": {"done": "done"},
        }
        s["qa_gate"]["next"]["approved"] = "note"

    _refused(_stages(change), names="note", says="to_status_category")


def test_v15_a_with_value_of_the_wrong_type_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["comment"] = {
            "kind": "effect",
            "effect": "ticket.comment",
            "with": {"template": 5},
            "next": {"done": "implement"},
        }
        s["ask"]["next"]["resumed"] = "comment"

    _refused(_stages(change), names="comment", says="template")


def test_v15_an_ident_with_value_must_look_like_an_ident() -> None:
    def change(s: dict[str, Any]) -> None:
        s["comment"] = {
            "kind": "effect",
            "effect": "ticket.comment",
            "with": {"template": "Not An Ident"},
            "next": {"done": "triage"},
        }
        s["ask"]["next"]["resumed"] = "comment"

    _refused(_stages(change), names="comment", says="template")


def test_v15_a_with_on_an_effect_that_takes_none_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["promote"] = {
            "kind": "effect",
            "effect": "branch.promote",
            "with": {"anything": 1},
            "requires_gates": ["review_gate"],
            "next": {"done": "merge"},
        }
        s["review_gate"]["next"]["approved"] = "promote"

    _refused(_stages(change), names="promote", says="anything")


def test_v15_sandbox_images_must_be_registered_when_a_registry_is_given() -> None:
    def change(d: dict[str, Any]) -> None:
        d["repo"] = {"name": "acme/ledger", "base": "main", "sandbox_image": "py312"}

    wf = _wf(change)
    ok = validate_structure(wf, manifest=MANIFEST, policy=_org(), sandbox_images={"py312"})
    assert ok == []
    bad = validate_structure(wf, manifest=MANIFEST, policy=_org(), sandbox_images={"node20"})
    assert any("repo.sandbox_image" in i.path and "py312" in i.message for i in bad)


# --- route order: the org owns the ranking --------------------------------------------------


def _routed(order: list[str]) -> Workflow:
    def change(s: dict[str, Any]) -> None:
        s["by_risk"] = {
            "kind": "route",
            "field": "risk",
            "order": order,
            "next": {"high": "review_gate", "default": "review_gate"},
        }
        s["panel"]["next"]["clean"] = "by_risk"

    return _wf(_stages(change))


def test_route_order_matching_the_orgs_passes() -> None:
    wf = _routed(["low", "medium", "high"])
    assert check_route_orders(wf, _org()) == []
    assert validate_structure(wf, manifest=MANIFEST, policy=_org()) == []


def test_route_order_with_the_org_values_reversed_is_refused() -> None:
    wf = _routed(["high", "medium", "low"])
    issues = check_route_orders(wf, _org())
    assert issues
    assert "by_risk" in _text(issues)
    assert "low" in _text(issues)
    assert issues[0].message in _text(validate_structure(wf, manifest=MANIFEST, policy=_org()))


def test_route_order_ranking_high_below_medium_is_refused() -> None:
    issues = check_route_orders(_routed(["low", "high", "medium"]), _org())
    assert "by_risk" in _text(issues)


def test_route_order_missing_an_org_value_is_refused() -> None:
    issues = check_route_orders(_routed(["low", "high"]), _org())
    assert "medium" in _text(issues)


def test_route_order_may_add_values_the_org_does_not_rank() -> None:
    assert check_route_orders(_routed(["low", "medium", "high", "critical"]), _org()) == []


def test_a_route_with_no_order_on_an_org_ranked_field_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["by_risk"] = {
            "kind": "route",
            "field": "risk",
            "next": {"high": "review_gate", "default": "review_gate"},
        }
        s["panel"]["next"]["clean"] = "by_risk"

    issues = validate_structure(_wf(_stages(change)), manifest=MANIFEST, policy=_org())
    assert any("by_risk" in i.path and "order" in i.message for i in issues), _text(issues)


def test_a_route_on_a_field_the_org_does_not_rank_is_left_alone() -> None:
    def change(s: dict[str, Any]) -> None:
        s["by_kind"] = {
            "kind": "route",
            "field": "issue_type",
            "order": ["bug", "story"],
            "next": {"bug": "review_gate", "default": "review_gate"},
        }
        s["panel"]["next"]["clean"] = "by_kind"

    assert _issues(_stages(change)) == []


def test_the_org_document_refuses_a_repeated_value_in_an_ordering() -> None:
    with pytest.raises(SchemaError):
        _org(lambda d: d["route_orders"].__setitem__("risk", ["low", "low"]))


def test_a_team_ordering_cannot_skip_a_when_gate() -> None:
    """The V17 search raises the ranking from the route's own order, so a reversed order would
    leave no value ranked above ``high``. The org ordering closes that."""

    def org(d: dict[str, Any]) -> None:
        d["teams"] = {
            "ledger": {
                "required_gates": [
                    {
                        "id": "review_gate",
                        "role": "reviewer",
                        "when": {"field": "risk", "value": "medium"},
                    }
                ]
            }
        }

    wf = _routed(["high", "medium", "low"])
    issues = validate_structure(wf, manifest=MANIFEST, policy=_org(org))
    assert any("by_risk" in i.path for i in issues), _text(issues)


# --- V17 additions: an org-required gate before branch.promote ------------------------------


def _with_promote(lists_gate: bool) -> Workflow:
    def change(s: dict[str, Any]) -> None:
        s["promote"] = {
            "kind": "effect",
            "effect": "branch.promote",
            "requires_gates": ["review_gate"] if lists_gate else ["qa_gate"],
            "next": {"done": "merge"},
        }
        s["review_gate"]["next"]["approved"] = "promote"

    return _wf(_stages(change))


def _require_review(d: dict[str, Any]) -> None:
    d["teams"] = {"ledger": {"required_gates": [{"id": "review_gate", "role": "reviewer"}]}}


def test_v17_a_required_gate_before_branch_promote_must_stay_in_its_requires_gates() -> None:
    policy = _org(_require_review)
    assert check_org_required_gates(_with_promote(True), policy, team="ledger") == []
    issues = check_org_required_gates(_with_promote(False), policy, team="ledger")
    assert any(i.path == "stages.promote.requires_gates" for i in issues), _text(issues)
    assert "review_gate" in _text(issues)


def test_v17_a_workflow_without_a_promote_is_unchanged() -> None:
    assert check_org_required_gates(_wf(), _org(_require_review), team="ledger") == []


# --- the catalog and the effect ports stay in step ------------------------------------------


def test_every_rule_names_the_stage_and_says_how_to_fix_it() -> None:
    def change(s: dict[str, Any]) -> None:
        s["triage"]["next"]["ready"] = "implemnt"

    for issue in _issues(_stages(change)):
        assert issue.path.startswith(("stages.", "start", "limits", "repo")), issue
        assert len(issue.message) > 20


def test_all_issues_are_reported_not_just_the_first() -> None:
    def change(s: dict[str, Any]) -> None:
        s["triage"]["next"]["ready"] = "implemnt"
        s["ask"]["next"]["resumed"] = "ask"
        del s["panel"]["next"]["degraded"]

    issues = _issues(_stages(change))
    assert len({i.path.split(".")[1] for i in issues if i.path.startswith("stages.")}) >= 3


# --- pass 1 ------------------------------------------------------------------------------


def _when_org(value: str = "medium", *, ranked: bool = True) -> Callable[[dict[str, Any]], None]:
    def org(d: dict[str, Any]) -> None:
        _custom_surfaces(d)
        d["teams"] = {
            "ledger": {
                "required_gates": [
                    {
                        "id": "change_gate",
                        "role": "change_manager",
                        "when": {"field": "risk", "value": value},
                    }
                ]
            }
        }
        if not ranked:
            del d["route_orders"]

    return org


def test_pass1_1_a_when_gate_needs_the_org_to_rank_its_field() -> None:
    with pytest.raises(SchemaError) as err:
        _org(_when_org(ranked=False))
    assert "route_orders.risk" in str(err.value)
    assert "change_gate" in str(err.value)


def test_pass1_1_the_ranking_must_contain_the_when_value() -> None:
    with pytest.raises(SchemaError) as err:
        _org(_when_org("critical"))
    assert "critical" in str(err.value)
    assert isinstance(_org(_when_org("medium")), OrgPolicy)


def _skipping_route(order: list[str], skip: str) -> Workflow:
    def change(s: dict[str, Any]) -> None:
        nxt = {v: "change_gate" for v in order if v != skip}
        nxt[skip] = "review_gate"
        nxt["default"] = "change_gate"
        s["by_risk"] = {"kind": "route", "field": "risk", "order": order, "next": nxt}
        s["panel"]["next"]["clean"] = "by_risk"
        s["panel"]["next"]["degraded"] = "by_risk"
        s["change_gate"] = _gate(
            "custom",
            ["change_manager"],
            {
                "approved": "review_gate",
                "changes_requested": {"to": "implement", "loop": "review_loop"},
                "rejected": "rejected_end",
            },
        )

    return _wf(_stages(change))


def test_pass1_2_a_team_value_below_the_orgs_highest_is_refused_naming_the_gate() -> None:
    wf = _skipping_route(["low", "critical", "medium", "high"], "critical")
    policy = _org(_when_org("medium"))
    issues = validate_structure(wf, manifest=MANIFEST, policy=policy)
    hits = [i for i in issues if "by_risk" in i.path and "critical" in i.message]
    assert hits, _text(issues)
    assert "change_gate" in hits[0].message
    assert "high" in hits[0].message  # says where to put it


def test_pass1_2_a_team_value_above_the_orgs_highest_is_allowed() -> None:
    wf = _skipping_route(["low", "medium", "high", "critical"], "critical")
    policy = _org(_when_org("medium"))
    assert check_route_orders(wf, policy) == []
    # the ordering is the team's to extend, but the V17 walk covers every value ranked above the
    # org's, so the route that sends critical past the gate is still refused
    issues = check_org_required_gates(wf, policy, team="ledger")
    assert any("change_gate" in i.message for i in issues), _text(issues)


def test_pass1_2_a_value_below_the_orgs_lowest_is_refused_too() -> None:
    wf = _skipping_route(["trivial", "low", "medium", "high"], "trivial")
    issues = check_route_orders(wf, _org(_when_org("medium")))
    hits = [i for i in issues if "trivial" in i.message]
    assert hits, _text(issues)
    assert "below low, the org's lowest ranked risk value" in hits[0].message


def test_pass2_a_team_value_directly_below_the_orgs_highest_is_refused() -> None:
    wf = _skipping_route(["low", "medium", "critical", "high"], "critical")
    issues = check_route_orders(wf, _org(_when_org("medium")))
    hits = [i for i in issues if "critical" in i.message]
    assert hits, _text(issues)
    assert "below high, the org's highest ranked risk value" in hits[0].message


def test_pass2_the_message_names_only_the_workflows_teams_gates() -> None:
    def org(d: dict[str, Any]) -> None:
        _when_org("medium")(d)
        d["teams"]["other"] = {
            "required_gates": [
                {
                    "id": "other_gate",
                    "role": "x",
                    "when": {"field": "risk", "value": "high"},
                }
            ]
        }

    wf = _skipping_route(["low", "critical", "medium", "high"], "critical")
    text = _text(check_route_orders(wf, _org(org)))
    assert "change_gate" in text
    assert "other_gate" not in text


def test_pass2_a_required_gate_without_when_does_not_end_the_ranking_check() -> None:
    def org(d: dict[str, Any]) -> None:
        d["teams"] = {
            "ledger": {
                "required_gates": [
                    {"id": "review_gate", "role": "reviewer"},
                    {
                        "id": "change_gate",
                        "role": "change_manager",
                        "when": {"field": "risk", "value": "critical"},
                    },
                ]
            }
        }

    with pytest.raises(SchemaError) as err:
        _org(org)  # critical is not ranked, and the unconditional entry came first
    assert "change_gate" in str(err.value)


def test_pass2_a_gate_timeout_of_only_remind_after_passes() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["timeouts"] = {"remind_after": "1d"}

    assert _issues(_stages(change)) == []


def test_pass2_a_stage_duration_equal_to_the_limit_passes() -> None:
    def run_age(d: dict[str, Any]) -> None:
        d["limits"]["max_run_age"] = "10d"
        d["stages"]["ask"]["timeout"] = "10d"

    assert _issues(run_age) == []

    def org_stage(s: dict[str, Any]) -> None:
        s["ask"]["timeout"] = "14d"  # equal to the org's max_stage_duration

    assert _issues(_stages(org_stage)) == []


def _promote_org(role: str, gate: str) -> Callable[[dict[str, Any]], None]:
    def org(d: dict[str, Any]) -> None:
        d["teams"] = {"ledger": {"required_gates": [{"id": gate, "role": role}]}}

    return org


def _qa_exits_refuse(s: dict[str, Any]) -> None:
    """After the merge every exit but QA's approval is a rejection, which V17 allows."""
    s["merge"]["next"]["conflict"] = "rejected_end"
    s["merge"]["next"]["stale"] = "rejected_end"
    s["qa_gate"]["next"]["changes_requested"] = "rejected_end"


def _promote_before_qa() -> Workflow:
    def change(s: dict[str, Any]) -> None:
        _qa_exits_refuse(s)
        s["promote"] = {
            "kind": "effect",
            "effect": "branch.promote",
            "requires_gates": ["review_gate"],
            "next": {"done": "merge"},
        }
        s["review_gate"]["next"]["approved"] = "promote"

    return _wf(_stages(change))


def test_pass1_4_a_promote_before_a_required_qa_gate_need_not_list_it() -> None:
    # QA comes after the promote that releases its secrets, so it cannot be listed there
    policy = _org(_promote_org("qa", "qa_gate"))
    assert check_org_required_gates(_promote_before_qa(), policy, team="ledger") == []


def test_pass1_4_a_promote_that_does_not_list_a_required_review_gate_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["promote"] = {
            "kind": "effect",
            "effect": "branch.promote",
            "requires_gates": ["qa_gate"],
            "next": {"done": "merge"},
        }
        s["review_gate"]["next"]["approved"] = "promote"

    policy = _org(_promote_org("reviewer", "review_gate"))
    issues = check_org_required_gates(_wf(_stages(change)), policy, team="ledger")
    assert [i.path for i in issues if "promote" in i.path] == ["stages.promote.requires_gates"]


def _promote_then_sec(*, sec_first: bool) -> Workflow:
    """A non-QA required gate ``sec`` beside the promote: after it, or before it."""

    def change(s: dict[str, Any]) -> None:
        sec_next = {
            "approved": "promote" if sec_first else "merge",
            "changes_requested": {"to": "implement", "loop": "review_loop"},
            "rejected": "closed",
        }
        s["sec"] = _gate("custom", ["security_officer"], sec_next)
        s["promote"] = {
            "kind": "effect",
            "effect": "branch.promote",
            "requires_gates": ["review_gate"],
            "next": {"done": "merge" if sec_first else "sec"},
        }
        s["review_gate"]["next"]["approved"] = "sec" if sec_first else "promote"
        s["merge"]["requires_gates"] = ["review_gate", "sec"]

    return _wf(_stages(change))


def test_pass1_4_a_promote_the_run_reaches_without_the_gate_is_not_preceded_by_it() -> None:
    # promote -> sec -> merge: the promote runs before sec decides, so it cannot list sec
    policy = _org(_promote_org("security_officer", "sec"))
    assert check_org_required_gates(_promote_then_sec(sec_first=False), policy, team="ledger") == []


def test_pass1_4_a_gate_that_precedes_the_promote_must_be_listed_by_it() -> None:
    policy = _org(_promote_org("security_officer", "sec"))
    issues = check_org_required_gates(_promote_then_sec(sec_first=True), policy, team="ledger")
    assert [i.path for i in issues] == ["stages.promote.requires_gates"], _text(issues)
    assert "sec" in issues[0].message


def test_pass1_5_a_rejection_cannot_reach_a_gated_effect_through_an_unrelated_gate() -> None:
    def change(s: dict[str, Any]) -> None:
        _custom_gate(s)
        s["review_gate"]["next"]["approved"] = "merge"
        s["review_gate"]["next"]["rejected"] = "sec"

    issues = _refused(
        _stages(change), org=_custom_surfaces, names="review_gate", says="sec -> merge"
    )
    assert issues


def test_pass1_5_passing_the_gate_the_effect_requires_is_still_fine() -> None:
    def change(s: dict[str, Any]) -> None:
        s["qa_gate"]["next"]["rejected"] = {"to": "review_gate", "loop": "review_loop"}

    assert _issues(_stages(change)) == []


def test_pass1_6_escalate_after_without_escalate_to_is_refused() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["timeouts"] = {"escalate_after": "2d"}

    issues = _refused(_stages(change), names="review_gate", says="escalate_to")
    assert any(i.path == "stages.review_gate.gate.timeouts.escalate_to" for i in issues)


def test_pass1_6_escalate_after_with_escalate_to_passes() -> None:
    def change(s: dict[str, Any]) -> None:
        s["review_gate"]["gate"]["timeouts"] = {"escalate_after": "2d", "escalate_to": "reviewer"}

    assert _issues(_stages(change)) == []


def _team(run_usd: float, stage_usd: dict[str, float] | None = None) -> TeamConfig:
    budgets: dict[str, Any] = {"run_usd": run_usd, "team_monthly_usd": 500}
    if stage_usd:
        budgets["stage_usd"] = stage_usd
    doc = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "ledger"},
        "budgets": budgets,
    }
    cfg = load_document(_dump(doc))
    assert isinstance(cfg, TeamConfig)
    return cfg


def test_pass1_7_the_entry_point_checks_the_teams_budgets() -> None:
    wf, pol = _wf(), _org()
    ok = validate_structure(wf, manifest=MANIFEST, policy=pol, team_config=_team(50))
    assert ok == []
    over = validate_structure(wf, manifest=MANIFEST, policy=pol, team_config=_team(51))
    assert any(i.path == "budgets.run_usd" for i in over), _text(over)


def test_pass1_7_the_entry_point_checks_each_stage_budget() -> None:
    wf, pol = _wf(), _org()
    over = validate_structure(
        wf, manifest=MANIFEST, policy=pol, team_config=_team(10, {"implement": 51})
    )
    assert any(i.path == "budgets.stage_usd.implement" for i in over), _text(over)
    fine = validate_structure(
        wf, manifest=MANIFEST, policy=pol, team_config=_team(10, {"implement": 50})
    )
    assert fine == []


def test_pass1_7_without_a_team_config_no_budget_is_checked() -> None:
    assert validate_structure(_wf(), manifest=MANIFEST, policy=_org()) == []


def _release(**with_: Any) -> Callable[[dict[str, Any]], None]:
    def change(s: dict[str, Any]) -> None:
        s["release"] = {
            "kind": "effect",
            "effect": "release.trigger",
            "with": with_,
            "requires_gates": ["qa_gate"],
            "next": {"done": "done", "stale": {"to": "implement", "loop": "fix_loop"}},
        }
        s["qa_gate"]["next"]["approved"] = "release"

    return _stages(change)


def test_pass1_8_a_blank_text_value_in_with_is_refused() -> None:
    assert _issues(_release(workflow="deploy.yml", sha_input="sha")) == []
    for blank in ("", "   ", "\t"):
        issues = _issues(_release(workflow=blank, sha_input="sha"))
        assert any(
            i.path == "stages.release.with.workflow" and "blank" in i.message for i in issues
        )


def test_pass1_v10_github_is_refused_off_review_gates_even_if_a_policy_lists_it() -> None:
    # the schema stops an org document listing it, so build the policy past the schema
    pol = _org()
    surfaces = {**pol.floors.decision_surfaces, "qa": ("ui", "github")}
    floors = pol.floors.model_copy(update={"decision_surfaces": surfaces})
    pol = pol.model_copy(update={"floors": floors})

    def change(s: dict[str, Any]) -> None:
        s["qa_gate"]["gate"]["decision_surfaces"] = ["github"]

    issues = validate_structure(_wf(_stages(change)), manifest=MANIFEST, policy=pol)
    assert any("only for review gates" in i.message and "qa_gate" in i.path for i in issues)


_RULE_FIXTURES: dict[str, tuple[str, Callable[[dict[str, Any]], None]]] = {
    "V1": ("triage", _stages(lambda s: s["triage"]["next"].__setitem__("ready", "nope"))),
    "V2": ("panel", _stages(lambda s: s["panel"]["next"].pop("degraded"))),
    "V3": ("merge", _stages(lambda s: s["merge"]["next"].__setitem__("stale", "implement"))),
    "V7": (
        "review_gate",
        _stages(
            lambda s: s["review_gate"]["gate"].__setitem__(
                "quorum", [{"role": "reviewer", "count": 1}, {"role": "reviewer", "count": 1}]
            )
        ),
    ),
    "V8": (
        "review_gate",
        _stages(lambda s: s["review_gate"]["next"].__setitem__("rejected", "merge")),
    ),
    "V9": ("ask", _stages(lambda s: s["ask"].__setitem__("timeout", "15d"))),
    "V10": (
        "qa_gate",
        _stages(lambda s: s["qa_gate"]["gate"].__setitem__("decision_surfaces", ["github"])),
    ),
    "V13": ("panel", _stages(lambda s: s["panel"].__setitem__("required", ["security_reviewer"]))),
    "V15": (
        "review_gate",
        _stages(lambda s: s["review_gate"]["gate"].__setitem__("eligible_roles", ["developer"])),
    ),
}


@pytest.mark.parametrize("rule", sorted(_RULE_FIXTURES))
def test_every_rule_names_the_stage_and_says_how_to_fix_it_for(rule: str) -> None:
    stage, change = _RULE_FIXTURES[rule]
    hits = [i for i in _issues(change) if stage in i.path]
    assert hits, f"{rule}: nothing names {stage}"
    for issue in hits:
        assert stage in issue.message, issue
        # a fix: an imperative after the problem, always set off by a semicolon or comma
        assert re.search(
            r"[;,] (add|remove|use|put|lower|shorten|name|list|send|fix|raise|set)\b", issue.message
        ), issue
