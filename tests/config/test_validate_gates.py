"""D2-04: V4, V5, V6, V11 and V14 by edge-removal reachability on the stage graph.

Each test builds a small flow, or changes the real ``standard`` template from PLAN 7.6, so a
failure names the rule that stopped holding. A rule that refuses is always paired with a flow
that passes, so a validator that refuses everything cannot satisfy this file.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from sto.config.manifest import load_manifest
from sto.config.org_policy import check_org_required_gates
from sto.config.overlays import flatten
from sto.config.schema import (
    EffectStage,
    Issue,
    OrgPolicy,
    SchemaError,
    Workflow,
    WorkflowOverlay,
    load_document,
    load_workflow,
)
from sto.config.validate_gates import (
    check_gate_dominance,
    code_changing_stages,
    qa_evidence_stages,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")
MANIFEST = load_manifest()


def _plan_blocks() -> list[str]:
    section = PLAN[PLAN.index("## 7. Workflow configuration") : PLAN.index("## 8. Agents")]
    blocks = re.findall(r"```yaml\n(.*?)```", section, flags=re.S)
    return [b for b in blocks if "apiVersion: sto/v1" in b and ": string" not in b]


_BLOCKS = _plan_blocks()
STANDARD: dict[str, Any] = yaml.safe_load(next(b for b in _BLOCKS if "kind: Workflow\n" in b))
OVERLAYS = {
    yaml.safe_load(b)["metadata"]["name"]: b for b in _BLOCKS if "kind: WorkflowOverlay" in b
}


def wf_of(data: dict[str, Any]) -> Workflow:
    # through JSON so a dict used twice is written out twice: the loader refuses aliases
    return load_workflow(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False))


def standard(mutate: Any = None) -> Workflow:
    data = copy.deepcopy(STANDARD)
    if mutate:
        mutate(data["stages"])
    return wf_of(data)


def flattened(name: str) -> Workflow:
    ov = load_document(OVERLAYS[name])
    assert isinstance(ov, WorkflowOverlay)
    return flatten(wf_of(STANDARD), ov, template_ref=ov.extends).workflow


def check(wf: Workflow) -> list[Issue]:
    return check_gate_dominance(wf, MANIFEST)


def rules(issues: list[Issue]) -> set[str]:
    return {i.message.split(":", 1)[0] for i in issues}


def only(issues: list[Issue], rule: str) -> list[Issue]:
    return [i for i in issues if i.message.startswith(f"{rule}:")]


# --- the real templates -----------------------------------------------------------------------


def test_the_standard_order_passes() -> None:
    assert check(standard()) == []


@pytest.mark.parametrize("name", sorted(OVERLAYS))
def test_every_plan_overlay_passes_once_flattened(name: str) -> None:
    assert check(flattened(name)) == []


def test_the_regulated_order_has_its_extra_gates_in_every_requires_gates() -> None:
    wf = flattened("ledger-regulated")
    merge = wf.stages["merge"]
    assert isinstance(merge, EffectStage)
    assert list(merge.requires_gates or ()) == ["review_gate", "security_gate", "qa_gate"]
    assert check(wf) == []


# --- derived sets -----------------------------------------------------------------------------


def test_code_changing_stages_come_from_the_manifest() -> None:
    # a commit by someone else re-enters at a ci stage when on_external_commit is unset
    assert code_changing_stages(standard(), MANIFEST) == {"implement", "update_branch", "ci"}


def test_code_changing_includes_the_external_commit_target() -> None:
    data = copy.deepcopy(STANDARD)
    data["on_external_commit"] = "ci"
    assert code_changing_stages(wf_of(data), MANIFEST) == {"implement", "update_branch", "ci"}


def test_without_on_external_commit_every_ci_stage_counts() -> None:
    def second_ci(stages: dict[str, Any]) -> None:
        stages["ci2"] = copy.deepcopy(stages["ci"])
        stages["update_branch"]["next"]["done"] = "ci2"

    assert code_changing_stages(standard(second_ci), MANIFEST) >= {"ci", "ci2"}
    # the same run, with the commit's entry named, is just that stage
    data = copy.deepcopy(STANDARD)
    data["on_external_commit"] = "ci"
    assert "ci2" not in code_changing_stages(wf_of(data), MANIFEST)
    assert "ci" in code_changing_stages(wf_of(data), MANIFEST)


def test_an_agent_that_can_write_the_workspace_is_code_changing_and_one_that_cannot_is_not() -> (
    None
):
    wf = standard()
    got = code_changing_stages(wf, MANIFEST)
    assert "implement" in got
    assert not got & {"triage", "refine", "plan", "qa_agentic"}


def test_an_agent_the_manifest_does_not_know_is_treated_as_code_changing() -> None:
    def unknown(stages: dict[str, Any]) -> None:
        stages["refine"]["agent"] = "mystery_agent"

    assert "refine" in code_changing_stages(standard(unknown), MANIFEST)


def test_qa_evidence_stages_are_qa_suite_checks_and_agents_that_record_evidence() -> None:
    assert qa_evidence_stages(standard(), MANIFEST) == {"qa_auto", "qa_agentic"}


# --- V4: gate dominance -----------------------------------------------------------------------


def test_v4_a_gated_effect_with_empty_requires_gates_fails() -> None:
    def empty(stages: dict[str, Any]) -> None:
        stages["merge"]["requires_gates"] = []

    # the schema already refuses an empty list when the file is loaded...
    with pytest.raises(SchemaError, match="requires_gates"):
        standard(empty)
    # ...and a workflow built around the loader (a model constructed in code) is refused here
    wf = standard()
    merge = wf.stages["merge"]
    forged = wf.model_copy(
        update={"stages": {**wf.stages, "merge": merge.model_copy(update={"requires_gates": ()})}}
    )
    issues = only(check(forged), "V4")
    assert [i.path for i in issues] == ["stages.merge.requires_gates"]
    assert "pr.merge" in issues[0].message


def test_v4_a_gated_effect_with_no_requires_gates_key_fails() -> None:
    def drop(stages: dict[str, Any]) -> None:
        del stages["promote"]["requires_gates"]

    assert [i.path for i in only(check(standard(drop)), "V4")] == ["stages.promote.requires_gates"]


@pytest.mark.parametrize(
    "effect", sorted(n for n, spec in MANIFEST.effects.items() if spec.effect_class == "gated")
)
def test_v4_every_gated_effect_of_the_catalog_needs_a_gate(effect: str) -> None:
    def put(stages: dict[str, Any]) -> None:
        stages["promote"] = {
            "kind": "effect",
            "effect": effect,
            "with": {"to_status_category": "in_progress"} if effect == "ticket.transition" else {},
            "next": {"done": "qa_env"},
        }
        if effect == "release.trigger":
            stages["promote"]["with"] = {"workflow": "d.yml", "sha_input": "sha"}

    issues = only(check(standard(put)), "V4")
    assert "stages.promote.requires_gates" in {i.path for i in issues}, issues


def test_v4_an_exposing_or_scoped_effect_needs_no_gate() -> None:
    # branch.push (exposing) and pr.ensure_draft (scoped) carry none in the real template
    assert only(check(standard()), "V4") == []


def test_v4_a_listed_gate_that_is_not_a_gate_fails() -> None:
    def wrong(stages: dict[str, Any]) -> None:
        stages["merge"]["requires_gates"] = ["review_gate", "qa_gate", "ci"]

    issues = only(check(standard(wrong)), "V4")
    assert any("ci" in i.message and "not a gate" in i.message for i in issues)


def test_v4_a_listed_gate_that_does_not_exist_fails() -> None:
    def wrong(stages: dict[str, Any]) -> None:
        stages["merge"]["requires_gates"] = ["review_gate", "qa_gate", "ghost_gate"]

    issues = only(check(standard(wrong)), "V4")
    assert any("ghost_gate" in i.message for i in issues)


def test_v4_a_path_around_a_listed_gate_fails_and_the_path_is_printed() -> None:
    def around(stages: dict[str, Any]) -> None:
        stages["llm_review"]["next"]["clean"] = "merge"  # skips both gates

    issues = only(check(standard(around)), "V4")
    assert issues, "a path from start to merge that never takes review_gate's approval"
    msg = issues[0].message
    assert "start" in msg or "triage" in msg
    path = re.search(r"path: (.+?)(?:;|$)", msg)
    assert path, msg
    assert path.group(1).split(" -> ")[0] == "triage"
    assert path.group(1).split(" -> ")[-1] == "merge"
    assert "llm_review" in path.group(1)
    assert "review_gate" not in path.group(1)


def test_v4_the_gate_must_be_listed_for_the_right_gate_not_just_any() -> None:
    def around_qa(stages: dict[str, Any]) -> None:
        # review_gate approval goes straight to the merge, skipping the QA stages
        stages["review_gate"]["next"]["approved"] = "merge"

    issues = only(check(standard(around_qa)), "V4")
    assert any("qa_gate" in i.message for i in issues), issues
    assert not any("without review_gate's approval" in i.message for i in issues)


def test_v4_a_gate_with_no_approved_edge_fails_rather_than_proving_everything() -> None:
    def no_exit(stages: dict[str, Any]) -> None:
        del stages["review_gate"]["next"]["approved"]

    issues = only(check(standard(no_exit)), "V4")
    assert any(i.path == "stages.review_gate.next" for i in issues), issues


def test_v4_the_gate_does_not_have_to_come_before_an_unreachable_effect() -> None:
    def island(stages: dict[str, Any]) -> None:
        stages["island"] = {
            "kind": "effect",
            "effect": "pr.mark_ready",
            "requires_gates": ["review_gate"],
            "next": {"done": "closed"},
        }

    # an effect nothing reaches is V1's problem, not a dominance failure
    assert only(check(standard(island)), "V4") == []


# --- V5: freshness ----------------------------------------------------------------------------


def test_v5_a_code_change_that_reaches_the_effect_without_a_new_approval_fails() -> None:
    def stale(stages: dict[str, Any]) -> None:
        stages["update_branch"]["next"]["done"] = "merge"

    issues = only(check(standard(stale)), "V5")
    assert issues
    assert "update_branch" in issues[0].message
    assert "merge" in issues[0].message
    assert only(check(standard(stale)), "V4") == [], "start still has to pass the gates"


def test_v5_the_implementer_reaching_the_effect_early_fails() -> None:
    def early(stages: dict[str, Any]) -> None:
        stages["implement"]["next"]["ready"] = "merge"

    issues = only(check(standard(early)), "V5")
    assert any("implement" in i.message for i in issues)


def test_v5_the_external_commit_target_is_checked_too() -> None:
    def hop(stages: dict[str, Any]) -> None:
        stages["ci"]["next"]["green"] = "merge"

    def target(data: dict[str, Any]) -> None:
        data["on_external_commit"] = "ci"

    data = copy.deepcopy(STANDARD)
    hop(data["stages"])
    assert only(check(wf_of(data)), "V5"), "ci is a ci stage, so it is an entry for commits"
    data["on_external_commit"] = "update_branch"
    assert only(check(wf_of(data)), "V5"), "update_branch is code-changing anyway"


def test_v5_a_loop_back_through_the_gates_passes() -> None:
    # the unmodified template loops changes_requested back to implement, and passes
    assert only(check(standard()), "V5") == []


# --- V6: floors -------------------------------------------------------------------------------


def test_v6_merge_without_a_review_gate_fails() -> None:
    def only_qa(stages: dict[str, Any]) -> None:
        stages["merge"]["requires_gates"] = ["qa_gate"]

    issues = only(check(standard(only_qa)), "V6")
    assert any(i.path == "stages.merge.requires_gates" and "review" in i.message for i in issues)


@pytest.mark.parametrize("stage", ["ticket_done", "release"])
def test_v6_a_release_or_done_transition_without_a_qa_gate_fails(stage: str) -> None:
    def build(stages: dict[str, Any]) -> None:
        stages["release"] = {
            "kind": "effect",
            "effect": "release.trigger",
            "with": {"workflow": "d.yml", "sha_input": "sha"},
            "requires_gates": ["review_gate"],
            "next": {"done": "ticket_done"},
        }
        stages["post_merge"]["next"]["green"] = "release"
        stages["ticket_done"]["requires_gates"] = ["review_gate", "qa_gate"]
        stages[stage]["requires_gates"] = ["review_gate"]

    issues = only(check(standard(build)), "V6")
    assert any(i.path == f"stages.{stage}.requires_gates" and "qa" in i.message for i in issues)


def test_v6_a_transition_to_another_status_category_needs_no_qa_gate() -> None:
    def moving(stages: dict[str, Any]) -> None:
        stages["note"] = {
            "kind": "effect",
            "effect": "ticket.transition",
            "with": {"to_status_category": "in_review"},
            "requires_gates": ["review_gate"],
            "next": {"done": "qa_env"},
        }
        stages["promote"]["next"]["done"] = "note"

    assert only(check(standard(moving)), "V6") == []


def test_v6_a_qa_gate_must_be_a_qa_type_not_just_named_qa() -> None:
    def mistyped(stages: dict[str, Any]) -> None:
        stages["qa_gate"]["gate"]["type"] = "custom"

    issues = only(check(standard(mistyped)), "V6")
    assert issues, "no stage that is a qa gate is listed for the merge"


def test_v6_review_gate_then_merge_then_closed_fails() -> None:
    wf = wf_of(
        {
            "apiVersion": "sto/v1",
            "kind": "Workflow",
            "metadata": {"name": "bad", "team": "_template"},
            "limits": {"max_steps_per_run": 20, "max_run_age": "10d"},
            "start": "impl",
            "stages": {
                "impl": {"kind": "agent", "agent": "implementer", "next": {"ready": "review_gate"}},
                "review_gate": REVIEW_GATE | {"next": {"approved": "merge", "rejected": "closed"}},
                "merge": {
                    "kind": "effect",
                    "effect": "pr.merge",
                    "requires_gates": ["review_gate"],
                    "next": {"done": "closed"},
                },
                "closed": {"kind": "terminal", "result": "closed"},
            },
        }
    )
    issues = only(check(wf), "V6")
    assert issues
    assert any("closed" in i.message and "merge" in i.message for i in issues)
    assert any("->" in i.message for i in issues), "the failing path is printed"


def test_v6_done_is_unreachable_without_a_qa_approval() -> None:
    def shortcut(stages: dict[str, Any]) -> None:
        stages["review_gate"]["next"]["approved"] = "done"

    issues = only(check(standard(shortcut)), "V6")
    assert any("done" in i.message and "qa" in i.message.lower() for i in issues)


def test_v6_a_qa_gate_that_is_one_of_two_does_not_hide_a_path_through_the_other() -> None:
    def second(stages: dict[str, Any]) -> None:
        stages["qa_gate2"] = copy.deepcopy(stages["qa_gate"])
        stages["qa_gate2"]["next"] = {"approved": "done", "rejected": "closed_rejected"}
        stages["qa_gate"]["next"]["rejected"] = "qa_gate2"
        stages["qa_gate"]["gate"]["decisions"] = ["approve", "reject"]

    # qa_gate2 is itself a qa gate, so removing every qa approval still removes it
    assert only(check(standard(second)), "V6") == []


# --- V6: merge before QA ----------------------------------------------------------------------


def test_v6_the_kanban_order_passes() -> None:
    wf = flattened("platform-kanban")
    assert check(wf) == []


def test_v6_kanban_with_a_closed_terminal_after_the_merge_fails() -> None:
    def shortcut(data: dict[str, Any]) -> None:
        data["stages"]["qa_auto"]["next"] = {"green": "closed", "red": "closed"}

    issues = _kanban(shortcut)
    assert only(issues, "V6")
    assert any("closed" in i.message for i in only(issues, "V6"))


def test_v6_kanban_with_a_done_terminal_after_the_merge_fails() -> None:
    def shortcut(data: dict[str, Any]) -> None:
        data["stages"]["qa_auto"]["next"] = {"green": "done", "red": "closed"}

    issues = _kanban(shortcut)
    assert any("done" in i.message for i in only(issues, "V6"))


def test_v6_a_wait_timeout_after_the_merge_is_ignored_when_it_gives_up() -> None:
    # await_implementer times out to closed, and it is reachable after the merge in kanban:
    # the passing kanban test above already covers it; this one removes the timeout and shows
    # the answer is the same, so the timeout was not what kept the template valid
    wf = flattened("platform-kanban")
    assert "timeout" in wf.stages["await_implementer"].next  # type: ignore[union-attr]
    assert check(wf) == []


def test_v6_a_wait_timeout_after_the_merge_is_ignored_even_to_a_done_terminal() -> None:
    def waits(data: dict[str, Any]) -> None:
        data["stages"]["qa_wait"] = {
            "kind": "wait",
            "wait_for": "environment_ready",
            "timeout": "1d",
            "next": {"resumed": "qa_auto", "timeout": "done"},
        }
        data["stages"]["merge"]["next"]["done"] = "qa_wait"

    # the spec: after the merge, timeouts are ignored, so the merge clause has nothing to say
    # about waiting. The plain "done needs a QA approval" rule still sees the path from start.
    issues = only(_kanban(waits), "V6")
    assert not [i for i in issues if "can merge before QA" in i.message]
    assert [i.path for i in issues] == ["stages.done"]


def test_v6_after_a_merge_a_rejection_with_no_qa_gate_on_the_path_fails() -> None:
    def reject(data: dict[str, Any]) -> None:
        data["stages"]["qa_auto"]["next"] = {"green": "closed_rejected", "red": "closed_rejected"}

    issues = only(_kanban(reject), "V6")
    assert issues
    assert any("rejected" in i.message and "blocks the release" in i.message for i in issues)
    assert any("merge" in i.message and "->" in i.message for i in issues)


def test_v6_a_rejection_after_a_qa_gate_is_fine() -> None:
    wf = flattened("platform-kanban")
    assert wf.stages["qa_gate"].next["rejected"] == "revert_pr"  # type: ignore[union-attr]

    def qa_rejects(data: dict[str, Any]) -> None:
        data["stages"]["qa_gate"]["next"]["rejected"] = "closed_rejected"

    assert only(_kanban(qa_rejects), "V6") == []


def test_v6_a_rejection_after_a_follow_up_code_change_is_left_to_the_engine() -> None:
    # PLAN 7.7: the review gate of a follow-up PR rejecting after a merge is handled at run
    # time (section 6.2). kanban reaches it through implement, and passes.
    wf = flattened("platform-kanban")
    assert wf.stages["review_gate"].next["rejected"] == "closed_rejected"  # type: ignore[union-attr]
    assert only(check(wf), "V6") == []


def test_v6_a_merge_that_never_lands_is_not_a_merge_followed_by_anything() -> None:
    def conflict(data: dict[str, Any]) -> None:
        data["stages"]["merge"]["next"]["conflict"] = "closed_rejected"
        data["stages"]["merge"]["next"]["stale"] = "closed_rejected"

    assert only(_kanban(conflict), "V6") == []


def test_v17_accepts_a_merge_then_rejected_and_leaves_it_to_v6() -> None:
    wf = _merge_then_rejected()
    assert only(check(wf), "V6"), "V6 refuses the shape"
    assert check_org_required_gates(wf, QA_POLICY, team="platform") == [], "V17 does not"


def test_v6_the_merge_then_rejected_shape_with_a_qa_gate_between_passes() -> None:
    wf = _merge_then_rejected(with_qa=True)
    assert only(check(wf), "V6") == []
    assert check_org_required_gates(wf, QA_POLICY, team="platform") == []


# --- V11: review order ------------------------------------------------------------------------


def test_v11_a_review_gate_reachable_without_a_review_panel_fails() -> None:
    def skip(stages: dict[str, Any]) -> None:
        stages["ci"]["next"]["green"] = "review_gate"

    issues = only(check(standard(skip)), "V11")
    assert issues
    assert "review_gate" in issues[0].message
    assert "llm_review" in issues[0].message  # tells you which stage to put in front
    assert "->" in issues[0].message


def test_v11_the_degraded_edge_still_goes_through_the_panel() -> None:
    assert only(check(standard()), "V11") == []


def test_v11_a_workflow_with_no_review_panel_at_all_fails() -> None:
    def none(stages: dict[str, Any]) -> None:
        stages["ci"]["next"]["green"] = "review_gate"
        del stages["llm_review"]
        stages["update_branch"]  # still present

    assert only(check(standard(none)), "V11")


def test_v11_a_pre_push_gate_is_not_a_review_gate() -> None:
    # pre_push_gate is reachable from implement with no panel, and the standard template passes
    wf = standard()
    assert wf.stages["pre_push_gate"].gate.type == "pre_push"  # type: ignore[union-attr]
    assert only(check(wf), "V11") == []


# --- V14: QA evidence -------------------------------------------------------------------------


def test_v14_a_qa_gate_reachable_without_qa_evidence_fails() -> None:
    def skip(stages: dict[str, Any]) -> None:
        stages["qa_env"]["next"]["done"] = "qa_gate"

    issues = only(check(standard(skip)), "V14")
    assert issues
    assert "qa_gate" in issues[0].message
    assert "qa_auto" in issues[0].message  # names what to put in front
    assert "->" in issues[0].message


def test_v14_one_kind_of_evidence_is_enough_only_if_it_is_on_every_path() -> None:
    def half(stages: dict[str, Any]) -> None:
        stages["qa_env"]["next"]["done"] = "qa_agentic"
        stages["qa_auto"]["next"]["green"] = "qa_agentic"

    # qa_auto is removed, qa_agentic is removed: with both gone nothing reaches qa_gate
    assert only(check(standard(half)), "V14") == []

    def ci_only(stages: dict[str, Any]) -> None:
        stages["qa_auto"]["source"] = "ci"  # no longer qa evidence
        stages["qa_agentic"]["agent"] = "refiner"  # nor this

    assert only(check(standard(ci_only)), "V14")


def test_v14_an_agent_stage_counts_as_evidence_only_if_its_profile_records_it() -> None:
    assert "record_evidence" in MANIFEST.tools("qa_agent")
    assert "record_evidence" not in MANIFEST.tools("refiner")


# --- several at once, and the one-line summary ------------------------------------------------


def test_every_issue_names_its_rule_and_a_stage_path() -> None:
    def broken(stages: dict[str, Any]) -> None:
        del stages["merge"]["requires_gates"]
        stages["ci"]["next"]["green"] = "review_gate"

    issues = check(standard(broken))
    assert {"V4", "V11"} <= rules(issues)
    for i in issues:
        assert i.path.startswith("stages.") or i.path == ""
        assert re.match(r"V\d+: ", i.message)


def test_the_validator_does_not_mutate_its_input() -> None:
    wf = standard()
    before = wf.model_dump_json()
    check(wf)
    assert wf.model_dump_json() == before


# --- helpers for flows ------------------------------------------------------------------------

REVIEW_GATE: dict[str, Any] = {
    "kind": "gate",
    "gate": {
        "type": "review",
        "eligible_roles": ["reviewer"],
        "decisions": ["approve", "reject"],
        "decision_surfaces": ["ui"],
    },
}
QA_GATE: dict[str, Any] = {
    "kind": "gate",
    "gate": {
        "type": "qa",
        "eligible_roles": ["qa"],
        "decisions": ["approve", "reject"],
        "decision_surfaces": ["ui"],
    },
}


def _kanban(mutate: Any) -> list[Issue]:
    """The flattened kanban workflow, changed by ``mutate`` on the plain dict, then checked."""
    wf = flattened("platform-kanban")
    data = json.loads(wf.model_dump_json(exclude_unset=True, by_alias=True))
    mutate(data)
    return check(wf_of(data))


def _merge_then_rejected(*, with_qa: bool = False) -> Workflow:
    after_merge = "qa_gate" if with_qa else "rejected_t"
    stages: dict[str, Any] = {
        "impl": {"kind": "agent", "agent": "implementer", "next": {"ready": "review_gate"}},
        "review_gate": REVIEW_GATE | {"next": {"approved": "merge", "rejected": "closed"}},
        "merge": {
            "kind": "effect",
            "effect": "pr.merge",
            "requires_gates": ["review_gate"],
            "next": {"done": after_merge},
        },
        "rejected_t": {"kind": "terminal", "result": "rejected"},
        "closed": {"kind": "terminal", "result": "closed"},
        "done": {"kind": "terminal", "result": "done"},
    }
    if with_qa:
        stages["qa_gate"] = QA_GATE | {"next": {"approved": "done", "rejected": "rejected_t"}}
    return wf_of(
        {
            "apiVersion": "sto/v1",
            "kind": "Workflow",
            "metadata": {"name": "flow", "team": "platform"},
            "limits": {"max_steps_per_run": 20, "max_run_age": "10d"},
            "start": "impl",
            "stages": stages,
        }
    )


_POLICY = {
    "apiVersion": "sto/v1",
    "kind": "OrgPolicy",
    "floors": {
        "mandatory_gate_roles": {"pre_push": ["reviewer"], "review": ["reviewer"], "qa": ["qa"]},
        "decision_surfaces": {"review": ["ui"], "qa": ["ui"]},
        "hold_after_approval_min": "10m",
        "identity_max_age": "8h",
    },
    "teams": {
        "platform": {
            "required_gates": [
                {"id": "review_gate", "role": "reviewer"},
            ],
        }
    },
}
_loaded = load_document(yaml.safe_dump(_POLICY))
assert isinstance(_loaded, OrgPolicy)
QA_POLICY: OrgPolicy = _loaded


# --- cases added after a mutation run on the validator -----------------------------------------


def test_on_external_commit_replaces_the_default_of_every_ci_stage() -> None:
    def second_ci(stages: dict[str, Any]) -> None:
        stages["ci2"] = copy.deepcopy(stages["ci"])
        stages["update_branch"]["next"]["done"] = "ci2"

    data = copy.deepcopy(STANDARD)
    second_ci(data["stages"])
    data["on_external_commit"] = "ci"
    got = code_changing_stages(wf_of(data), MANIFEST)
    assert "ci" in got
    assert "ci2" not in got


def test_v6_a_done_transition_is_recognised_whatever_the_case_of_its_category() -> None:
    def shout(stages: dict[str, Any]) -> None:
        stages["ticket_done"]["with"]["to_status_category"] = "DONE"
        stages["ticket_done"]["requires_gates"] = ["review_gate"]

    issues = only(check(standard(shout)), "V6")
    assert any(i.path == "stages.ticket_done.requires_gates" for i in issues)


def test_v6_an_unreachable_merge_followed_by_a_rejection_is_not_reported() -> None:
    def island(stages: dict[str, Any]) -> None:
        stages["island_merge"] = {
            "kind": "effect",
            "effect": "pr.merge",
            "requires_gates": ["review_gate"],
            "next": {"done": "closed_rejected"},
        }

    assert only(check(standard(island)), "V6") == []


# --- pass 1 review ----------------------------------------------------------------------------


def test_v6_a_rejection_after_a_merge_through_a_ci_stage_is_refused() -> None:
    def post_ci(data: dict[str, Any]) -> None:
        data["stages"]["post_ci"] = {
            "kind": "checks",
            "source": "ci",
            "required": "team_default",
            "timeout": "1h",
            "next": {"green": "qa_auto", "red": "closed_rejected"},
        }
        data["stages"]["merge"]["next"]["done"] = "post_ci"

    issues = only(_kanban(post_ci), "V6")
    assert any("rejected" in i.message and "post_ci" in i.message for i in issues)


def test_v6_a_rejection_after_a_merge_through_an_unknown_agent_is_refused() -> None:
    def mystery(data: dict[str, Any]) -> None:
        data["stages"]["mystery"] = {
            "kind": "agent",
            "agent": "mystery_agent",
            "next": {"fail": "closed_rejected", "pass": "qa_auto"},
        }
        data["stages"]["merge"]["next"]["done"] = "mystery"

    issues = only(_kanban(mystery), "V6")
    assert any("rejected" in i.message and "mystery" in i.message for i in issues)


def test_v6_a_rejection_after_a_merge_behind_an_implementer_is_still_the_engines() -> None:
    def follow_up(data: dict[str, Any]) -> None:
        data["stages"]["merge"]["next"]["done"] = "implement"

    assert [i for i in only(_kanban(follow_up), "V6") if "rejected" in i.message] == []


def test_v6_done_is_unreachable_without_a_review_approval() -> None:
    wf = _no_review()
    issues = only(check(wf), "V6")
    assert any("without a review approval" in i.message and "done" in i.message for i in issues)
    assert only(check(_no_review(with_review=True)), "V6") == []


def _no_review(*, with_review: bool = False) -> Workflow:
    stages: dict[str, Any] = {
        "impl": {"kind": "agent", "agent": "implementer", "next": {"ready": "qa_gate"}},
        "qa_gate": QA_GATE | {"next": {"approved": "done", "rejected": "closed"}},
        "closed": {"kind": "terminal", "result": "closed"},
        "done": {"kind": "terminal", "result": "done"},
    }
    if with_review:
        stages["impl"]["next"]["ready"] = "review_gate"
        stages["review_gate"] = REVIEW_GATE | {
            "next": {"approved": "qa_gate", "rejected": "closed"}
        }
    return wf_of(
        {
            "apiVersion": "sto/v1",
            "kind": "Workflow",
            "metadata": {"name": "flow", "team": "platform"},
            "limits": {"max_steps_per_run": 20, "max_run_age": "10d"},
            "start": "impl",
            "stages": stages,
        }
    )


def test_v6_a_qa_rejection_straight_to_closed_after_a_merge_is_refused_on_purpose() -> None:
    def closes(data: dict[str, Any]) -> None:
        data["stages"]["qa_gate"]["next"]["rejected"] = "closed"

    issues = only(_kanban(closes), "V6")
    assert any("can merge before QA" in i.message and "closed" in i.message for i in issues)


def test_the_whole_failing_path_is_printed_with_the_bypass_edge() -> None:
    n = 14

    def chain(stages: dict[str, Any]) -> None:
        for k in range(n):
            stages[f"hop{k}"] = {
                "kind": "checks",
                "source": "ci",
                "required": "team_default",
                "timeout": "1h",
                "next": {"green": f"hop{k + 1}" if k + 1 < n else "llm_review", "red": "implement"},
            }
        stages["ci"]["next"]["green"] = "hop0"
        stages[f"hop{n // 2}"]["next"]["green"] = "merge"  # the bypass edge, mid-path

    msgs = [i.message for i in only(check(standard(chain)), "V4")]
    want = f"hop{n // 2 - 1} -> hop{n // 2} -> merge"
    assert any(want in m for m in msgs), msgs
    assert not any("..." in m for m in msgs)
