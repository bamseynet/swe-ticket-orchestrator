"""D2-02: overlays and flattening. Each refusal is a way a team could weaken a floor."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from sto.config.overlays import (
    FLOORS,
    Flattened,
    OverlayError,
    flatten,
    merge_patch,
)
from sto.config.schema import (
    SchemaError,
    Workflow,
    WorkflowOverlay,
    load_document,
    load_workflow,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")


def _plan_blocks() -> list[str]:
    section = PLAN[PLAN.index("## 7. Workflow configuration") : PLAN.index("## 8. Agents")]
    blocks = re.findall(r"```yaml\n(.*?)```", section, flags=re.S)
    return [b for b in blocks if "apiVersion: sto/v1" in b and ": string" not in b]


_BLOCKS = _plan_blocks()
STANDARD_TEXT = next(b for b in _BLOCKS if "kind: Workflow\n" in b)
OVERLAY_TEXTS = {
    yaml.safe_load(b)["metadata"]["name"]: b for b in _BLOCKS if "kind: WorkflowOverlay" in b
}
TEMPLATE = load_workflow(STANDARD_TEXT)


def overlay(text: str) -> WorkflowOverlay:
    doc = load_document(text)
    assert isinstance(doc, WorkflowOverlay)
    return doc


def make(patch: dict[str, Any], **head: Any) -> WorkflowOverlay:
    """A small overlay on ``standard@1`` that supplies what publishing needs."""
    body: dict[str, Any] = {
        "apiVersion": "sto/v1",
        "kind": "WorkflowOverlay",
        "metadata": {"name": "t", "team": "payments"},
        "extends": "standard@1",
        "intake": {"source": "github", "project": "example/p", "label": "agent-ready"},
        "repo": {"name": "example/p", "base": "main", "sandbox_image": "go1"},
    }
    body.update(patch)
    body.update(head)
    return overlay(yaml.safe_dump(body))


def stage_patch(stage: str, value: Any) -> WorkflowOverlay:
    return make({"stages": {stage: value}})


def issues_of(exc: OverlayError) -> str:
    return "\n".join(str(i) for i in exc.issues)


# --- merge rules: maps merge, lists replace, null removes (RFC 7386) -------------------------

MERGE_CASES = [
    # RFC 7386 appendix A, plus the cases PLAN 7.1 names
    ({"a": "b"}, {"a": "c"}, {"a": "c"}),
    ({"a": "b"}, {"b": "c"}, {"a": "b", "b": "c"}),
    ({"a": "b"}, {"a": None}, {}),
    ({"a": "b", "b": "c"}, {"a": None}, {"b": "c"}),
    ({"a": ["b"]}, {"a": "c"}, {"a": "c"}),
    ({"a": "c"}, {"a": ["b"]}, {"a": ["b"]}),
    ({"a": {"b": "c"}}, {"a": {"b": "d", "c": None}}, {"a": {"b": "d"}}),
    ({"a": [{"b": "c"}]}, {"a": [1]}, {"a": [1]}),
    ({"a": 1, "b": 2}, {"a": [], "b": {}}, {"a": [], "b": {}}),
    (["a", "b"], ["c", "d"], ["c", "d"]),
    ({"a": "b"}, ["c"], ["c"]),
    ({"a": "foo"}, None, None),
    ({"a": "foo"}, "bar", "bar"),
    ({"e": None}, {"a": 1}, {"e": None, "a": 1}),
    ([1, 2], {"a": "b", "c": None}, {"a": "b"}),
    ({}, {"a": {"bb": {"ccc": None}}}, {"a": {"bb": {}}}),
    # lists replace whole, they are not merged by element or concatenated
    ({"r": ["a", "b", "c"]}, {"r": ["z"]}, {"r": ["z"]}),
    ({"r": ["a"]}, {"r": []}, {"r": []}),
    # a null inside a list is a value, not a removal
    ({"r": [1]}, {"r": [1, None]}, {"r": [1, None]}),
    # a patch object over an absent or non-object value drops its nulls
    ({}, {"w": {"x": None, "y": 1}}, {"w": {"y": 1}}),
    ({"w": "s"}, {"w": {"x": None, "y": {"z": None}}}, {"w": {"y": {}}}),
    # a null for a key that is not there is a no-op
    ({"a": 1}, {"zz": None}, {"a": 1}),
    # nested maps merge key by key at every depth
    (
        {"s": {"gate": {"timeouts": {"a": 1, "b": 2}, "x": 1}}},
        {"s": {"gate": {"timeouts": {"b": 3}}}},
        {"s": {"gate": {"timeouts": {"a": 1, "b": 3}, "x": 1}}},
    ),
]


@pytest.mark.parametrize(("target", "patch", "expected"), MERGE_CASES)
def test_merge_patch_table(target: Any, patch: Any, expected: Any) -> None:
    before = copy.deepcopy(target)
    assert merge_patch(target, patch) == expected
    assert target == before, "the target is never changed in place"


def test_merge_patch_does_not_share_structure_with_its_inputs() -> None:
    patch = {"a": {"b": [1]}}
    out = merge_patch({}, patch)
    out["a"]["b"].append(2)
    assert patch == {"a": {"b": [1]}}


def test_stage_order_has_no_meaning_and_next_maps_merge() -> None:
    flat = flatten(TEMPLATE, stage_patch("triage", {"next": {"ready": "implement"}})).workflow
    edges = dict(flat.stages["triage"].next)  # type: ignore[union-attr]
    assert edges == {"ready": "implement", "needs_info": "await_info", "not_actionable": "closed"}


def test_lists_replace_in_a_stage() -> None:
    flat = flatten(TEMPLATE, stage_patch("llm_review", {"reviewers": ["correctness_reviewer"]}))
    assert tuple(flat.workflow.stages["llm_review"].reviewers) == ("correctness_reviewer",)  # type: ignore[union-attr]


def test_a_new_stage_is_added_and_a_null_stage_is_removed() -> None:
    new = {"kind": "terminal", "result": "closed"}
    flat = flatten(TEMPLATE, make({"stages": {"extra_end": new, "refine": None}})).workflow
    assert "extra_end" in flat.stages
    assert "refine" not in flat.stages


def test_removing_a_stage_that_is_not_there_changes_nothing() -> None:
    flat = flatten(TEMPLATE, stage_patch("no_such_stage", None)).workflow
    assert set(flat.stages) == set(TEMPLATE.stages)


def test_a_patch_that_changes_a_stage_kind_is_validated_after_the_merge() -> None:
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, stage_patch("triage", {"kind": "terminal", "result": "closed"}))
    assert "stages.triage" in issues_of(err.value)


# --- the three PLAN overlays -----------------------------------------------------------------


def test_the_plan_has_exactly_three_overlays() -> None:
    assert set(OVERLAY_TEXTS) == {"payments-scrum", "platform-kanban", "ledger-regulated"}


@pytest.mark.parametrize("name", sorted(OVERLAY_TEXTS))
def test_plan_overlay_flattens(name: str) -> None:
    ov = overlay(OVERLAY_TEXTS[name])
    result = flatten(TEMPLATE, ov)
    assert isinstance(result, Flattened)
    wf = result.workflow
    assert isinstance(wf, Workflow)
    assert wf.missing_for_publish() == []
    assert wf.metadata.name == name
    assert wf.start == TEMPLATE.start
    # the flat document is a plain Workflow: it survives a trip through the loader unchanged
    dumped = yaml.safe_dump(wf.model_dump(mode="json", by_alias=True, exclude_unset=True))
    assert load_document(dumped) == wf


def test_scrum_overlay_values() -> None:
    wf = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["payments-scrum"])).workflow
    panel = wf.stages["llm_review"]
    assert "pci_reviewer" in panel.reviewers  # type: ignore[union-attr]
    assert panel.required == TEMPLATE.stages["llm_review"].required  # type: ignore[union-attr]
    assert [(d.stage, d.check) for d in wf.definition_of_done][-1] == (
        "review_gate",
        "coverage_at_least",
    )


def test_kanban_overlay_values() -> None:
    wf = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["platform-kanban"])).workflow
    for gone in ("refine", "plan", "promote", "qa_env", "post_merge"):
        assert gone not in wf.stages
    assert wf.definition_of_done == ()
    assert dict(wf.limits.loops) == {**dict(TEMPLATE.limits.loops), "release_stale": 2}
    assert wf.limits.max_steps_per_run == 100
    assert wf.stages["triage"].model_tier == "fast"  # type: ignore[union-attr]
    assert "release" in wf.stages
    assert wf.stages["release"].kind == "effect"


def test_ledger_overlay_values() -> None:
    wf = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["ledger-regulated"])).workflow
    gate = wf.stages["review_gate"].gate  # type: ignore[union-attr]
    assert gate.type == "review"  # untouched keys of the template survive
    assert [(q.role, q.count) for q in gate.quorum or ()] == [("reviewer", 2)]
    assert "security_gate" in wf.stages
    assert wf.stages["llm_review"].fail_closed is True  # type: ignore[union-attr]


def test_flatten_of_an_empty_overlay_is_the_template() -> None:
    result = flatten(TEMPLATE, make({}, intake=None, repo=None), require_publishable=False)
    assert result.workflow.stages == TEMPLATE.stages
    assert result.workflow.limits == TEMPLATE.limits


def test_flatten_does_not_change_its_inputs() -> None:
    ov = overlay(OVERLAY_TEXTS["platform-kanban"])
    before_t, before_o = TEMPLATE.model_dump(), ov.model_dump()
    flatten(TEMPLATE, ov)
    assert TEMPLATE.model_dump() == before_t
    assert ov.model_dump() == before_o


def test_a_removal_is_not_dropped_on_the_way() -> None:
    """``exclude_none`` would turn every ``null`` removal into "leave it alone"."""
    ov = overlay(OVERLAY_TEXTS["platform-kanban"])
    assert ov.to_patch()["stages"]["refine"] is None
    assert "refine" not in flatten(TEMPLATE, ov).workflow.stages


def test_the_template_is_dumped_without_defaults_or_nulls() -> None:
    result = flatten(TEMPLATE, make({}))
    assert result.workflow.intake is not None
    dumped = result.workflow.model_dump(mode="json", by_alias=True, exclude_unset=True)
    assert load_document(yaml.safe_dump(dumped)) == result.workflow


# --- floors ----------------------------------------------------------------------------------


@pytest.mark.parametrize("gate", ["pre_push_gate", "review_gate", "qa_gate"])
def test_removing_a_mandatory_gate_fails(gate: str) -> None:
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, stage_patch(gate, None))
    text = issues_of(err.value)
    assert gate in text
    assert "floor" in text
    assert "mandatory" in text


@pytest.mark.parametrize(
    "patch",
    [
        {"gate": None},
        {"kind": "terminal", "result": "closed"},
        {"gate": {"type": "custom"}},
        {"kind": "effect", "effect": "notify"},
    ],
)
def test_turning_a_mandatory_gate_into_something_else_fails(patch: dict[str, Any]) -> None:
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, stage_patch("qa_gate", patch))
    assert "mandatory" in issues_of(err.value)


def test_a_custom_gate_can_be_removed() -> None:
    ledger = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["ledger-regulated"])).workflow
    assert "security_gate" in ledger.stages
    ov = make({"extends": "ledger-regulated@1", "stages": {"security_gate": None}})
    assert "security_gate" not in flatten(ledger, ov).workflow.stages


def test_separation_of_duties_null_is_a_floor_error_not_a_removal() -> None:
    ledger = overlay(OVERLAY_TEXTS["ledger-regulated"])
    base = flatten(TEMPLATE, ledger).workflow
    assert base.stages["review_gate"].gate.separation_of_duties is not None  # type: ignore[union-attr]
    ov = make(
        {
            "extends": "ledger-regulated@1",
            "stages": {"review_gate": {"gate": {"separation_of_duties": None}}},
        }
    )
    with pytest.raises(OverlayError) as err:
        flatten(base, ov)
    text = issues_of(err.value)
    assert "separation_of_duties" in text
    assert "floor" in text


def test_separation_of_duties_null_is_refused_even_when_the_template_has_none() -> None:
    ov = stage_patch("review_gate", {"gate": {"separation_of_duties": None}})
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, ov)
    assert "separation_of_duties" in issues_of(err.value)


def test_fail_closed_null_is_a_floor_error_not_false() -> None:
    ledger = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["ledger-regulated"])).workflow
    assert ledger.stages["llm_review"].fail_closed is True  # type: ignore[union-attr]
    ov = make({"extends": "ledger-regulated@1", "stages": {"llm_review": {"fail_closed": None}}})
    with pytest.raises(OverlayError) as err:
        flatten(ledger, ov)
    text = issues_of(err.value)
    assert "fail_closed" in text
    assert "floor" in text


@pytest.mark.parametrize(
    "path",
    [
        ("requires_gates",),
        ("fail_closed",),
        ("block_on",),
        ("gate", "quorum"),
        ("gate", "eligible_roles"),
        ("gate", "decision_surfaces"),
        ("gate", "separation_of_duties"),
    ],
)
def test_every_floor_key_refuses_null(path: tuple[str, ...]) -> None:
    patch: Any = None
    for key in reversed(path):
        patch = {key: patch}
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, stage_patch("review_gate", patch))
    assert "floor" in issues_of(err.value)


def test_floors_are_listed_with_a_reason() -> None:
    assert FLOORS
    for path, reason in FLOORS.items():
        assert path
        assert reason.strip()


def test_floor_errors_name_the_stage_and_the_fix() -> None:
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, stage_patch("llm_review", {"fail_closed": None}))
    (issue,) = err.value.issues
    assert issue.path == "stages.llm_review.fail_closed"
    assert "change its value" in issue.message


def test_all_floor_problems_are_reported_together() -> None:
    both = make(
        {"stages": {"qa_gate": None, "llm_review": {"fail_closed": None}}},
    )
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, both)
    assert len(err.value.issues) == 2


def test_a_new_stage_that_is_incomplete_is_refused_after_the_merge() -> None:
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, stage_patch("extra", {"kind": "wait", "wait_for": "human_answer"}))
    text = issues_of(err.value)
    assert "stages.extra" in text
    assert "timeout" in text


def test_overlay_error_is_a_schema_error_and_pickles() -> None:
    import pickle

    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, stage_patch("qa_gate", None))
    assert isinstance(err.value, SchemaError)
    again = pickle.loads(pickle.dumps(err.value))
    assert type(again) is OverlayError
    assert again.issues == err.value.issues


# --- the overlay must fit its template and be publishable ------------------------------------


def test_an_overlay_for_another_template_is_refused() -> None:
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, make({}, extends="other@1"))
    assert "other" in issues_of(err.value)
    assert "standard" in issues_of(err.value)


def test_a_flattened_workflow_without_intake_or_repo_is_not_publishable() -> None:
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, make({}, intake=None, repo=None))
    text = issues_of(err.value)
    assert "intake" in text
    assert "repo" in text


# --- provenance ------------------------------------------------------------------------------


def test_provenance_says_which_layer_set_each_value() -> None:
    result = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["platform-kanban"]))
    prov = result.provenance
    assert prov.source(("stages", "triage", "model_tier")) == "overlay:platform-kanban"
    assert prov.source(("stages", "triage", "kind")) == "standard@1"
    assert prov.source(("stages", "triage", "next", "ready")) == "overlay:platform-kanban"
    assert prov.source(("stages", "triage", "next", "needs_info")) == "standard@1"
    assert prov.source(("limits", "max_steps_per_run")) == "overlay:platform-kanban"
    assert prov.source(("limits", "loops", "release_stale")) == "overlay:platform-kanban"
    assert prov.source(("limits", "loops", "info")) == "standard@1"
    assert prov.source(("start",)) == "standard@1"
    assert prov.source(("intake", "source")) == "overlay:platform-kanban"
    assert prov.source(("metadata", "name")) == "overlay:platform-kanban"


def test_a_list_replaced_by_the_overlay_is_its_value_whole() -> None:
    prov = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["payments-scrum"])).provenance
    assert prov.source(("stages", "llm_review", "reviewers")) == "overlay:payments-scrum"
    assert prov.source(("stages", "llm_review", "required")) == "standard@1"


def test_removals_are_recorded() -> None:
    prov = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["platform-kanban"])).provenance
    assert ("stages", "refine") in prov.removed
    assert ("definition_of_done",) in prov.removed
    with pytest.raises(KeyError):
        prov.source(("stages", "refine"))


def test_every_value_of_the_flat_document_has_a_source() -> None:
    result = flatten(TEMPLATE, overlay(OVERLAY_TEXTS["ledger-regulated"]))
    doc = result.workflow.model_dump(mode="json", by_alias=True, exclude_unset=True)
    missing = [p for p in _leaves(doc) if p not in result.provenance.leaves]
    assert missing == []
    assert set(result.provenance.leaves.values()) == {"standard@1", "overlay:ledger-regulated"}


def _leaves(value: Any, path: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    if isinstance(value, dict) and value:
        return [p for k, v in value.items() for p in _leaves(v, (*path, k))]
    return [path]


# --- nulls nested in ``with``: flatten and load_document agree -------------------------------


def test_null_in_with_removes_the_key_when_merging() -> None:
    wf = flatten(TEMPLATE, stage_patch("merge", {"with": {"method": None, "other": 1}})).workflow
    assert dict(wf.stages["merge"].with_ or {}) == {"other": 1}  # type: ignore[union-attr]


def test_null_in_a_new_with_is_dropped_not_stored() -> None:
    wf = flatten(TEMPLATE, stage_patch("push", {"with": {"a": None, "b": 1}})).workflow
    assert dict(wf.stages["push"].with_ or {}) == {"b": 1}  # type: ignore[union-attr]
    again = load_document(
        yaml.safe_dump(wf.model_dump(mode="json", by_alias=True, exclude_unset=True))
    )
    assert again == wf


def test_a_null_item_in_a_with_list_is_a_value_to_both() -> None:
    wf = flatten(TEMPLATE, stage_patch("push", {"with": {"xs": [1, None]}})).workflow
    assert list(wf.stages["push"].with_["xs"]) == [1, None]  # type: ignore[union-attr,index]
    dumped = yaml.safe_dump(wf.model_dump(mode="json", by_alias=True, exclude_unset=True))
    assert load_document(dumped) == wf


def test_a_template_built_in_code_with_a_null_in_with_is_refused() -> None:
    text = STANDARD_TEXT.replace("with: { method: squash }", "with: { method: squash, x: null }")
    with pytest.raises(SchemaError):
        load_document(text)
    # model_copy skips validation, so flatten must catch what the loader would have caught
    bad_stage = TEMPLATE.stages["merge"].model_copy(
        update={"with_": {"method": "squash", "x": None}}
    )
    loose = TEMPLATE.model_copy(update={"stages": {**TEMPLATE.stages, "merge": bad_stage}})
    with pytest.raises(OverlayError) as err:
        flatten(loose, make({}))
    assert "stages.merge.with.x" in issues_of(err.value)


# --- preview deploys never name production ---------------------------------------------------

PREVIEW = {"kind": "effect", "effect": "env.deploy_preview", "requires_gates": ["review_gate"]}


@pytest.mark.parametrize(
    "with_",
    [
        {"workflow": "deploy-prod.yml"},
        {"environment": "production"},
        {"environment": "Production"},
        {"target": "eu_prod_1"},
        {"production": "yes"},
        {"nested": {"deep": ["staging", "prod"]}},
    ],
)
def test_deploy_preview_cannot_name_production(with_: dict[str, Any]) -> None:
    ov = stage_patch("qa_env", {**PREVIEW, "with": with_, "next": {"done": "qa_auto"}})
    with pytest.raises(OverlayError) as err:
        flatten(TEMPLATE, ov)
    text = issues_of(err.value)
    assert "stages.qa_env.with" in text
    assert "production" in text


@pytest.mark.parametrize("value", ["preview", "staging", "reproduce", "approved", "product"])
def test_other_words_are_not_production(value: str) -> None:
    ov = stage_patch("qa_env", {"with": {"environment": value}})
    assert flatten(TEMPLATE, ov).workflow.stages["qa_env"].kind == "effect"


def test_production_in_the_with_of_other_effects_is_not_this_rule() -> None:
    ov = stage_patch(
        "release",
        {
            "kind": "effect",
            "effect": "release.trigger",
            "with": {"workflow": "deploy-prod.yml", "sha_input": "s"},
            "requires_gates": ["qa_gate"],
            "next": {"done": "done"},
        },
    )
    assert flatten(TEMPLATE, ov).workflow.stages["release"].kind == "effect"
