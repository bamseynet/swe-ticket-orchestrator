"""D2-01: the workflow schema. Every refusal here is a path a team could use to weaken a gate."""

from __future__ import annotations

import copy
import datetime as dt
import json
import pickle
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import BaseModel

from sto.config import schema
from sto.config.schema import (
    OrgPolicy,
    SchemaError,
    TeamConfig,
    Workflow,
    WorkflowOverlay,
    load_document,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")


def _plan_blocks() -> list[str]:
    """Concrete YAML blocks of PLAN section 7. The section 7.2 shapes use types as values."""
    section = PLAN[PLAN.index("## 7. Workflow configuration") : PLAN.index("## 8. Agents")]
    blocks = re.findall(r"```yaml\n(.*?)```", section, flags=re.S)
    return [b for b in blocks if "apiVersion: sto/v1" in b and ": string" not in b]


PLAN_BLOCKS = _plan_blocks()


def _block_id(block: str) -> str:
    data = yaml.safe_load(block)
    return str(data.get("metadata", {}).get("name") or data["kind"])


STANDARD = next(b for b in PLAN_BLOCKS if "kind: Workflow\n" in b)


def _line_of(text: str, needle: str, occurrence: int = 1) -> int:
    hits = [i + 1 for i, ln in enumerate(text.splitlines()) if needle in ln]
    return hits[occurrence - 1]


def _refused(text: str) -> SchemaError:
    with pytest.raises(SchemaError) as info:
        load_document(text)
    return info.value


def _std_data() -> dict[str, Any]:
    data = yaml.safe_load(STANDARD)
    assert isinstance(data, dict)
    return copy.deepcopy(data)


# --- PLAN examples ---------------------------------------------------------------------------


def test_plan_examples_are_found() -> None:
    kinds = [yaml.safe_load(b)["kind"] for b in PLAN_BLOCKS]
    assert sorted(kinds) == sorted(
        [
            "Workflow",
            "WorkflowOverlay",
            "TeamConfig",
            "WorkflowOverlay",
            "WorkflowOverlay",
            "OrgPolicy",
        ]
    )


@pytest.mark.parametrize("block", PLAN_BLOCKS, ids=_block_id)
def test_plan_examples_parse(block: str) -> None:
    expected = {
        "Workflow": Workflow,
        "WorkflowOverlay": WorkflowOverlay,
        "TeamConfig": TeamConfig,
        "OrgPolicy": OrgPolicy,
    }[yaml.safe_load(block)["kind"]]
    assert isinstance(load_document(block), expected)


def test_standard_template_has_the_expected_shape() -> None:
    wf = load_document(STANDARD)
    assert isinstance(wf, Workflow)
    assert wf.start == "triage"
    assert len(wf.stages) == len(yaml.safe_load(STANDARD)["stages"]) == 27
    assert wf.stages["merge"].kind == "effect"
    assert wf.stages["review_gate"].kind == "gate"
    assert wf.limits.loops["human_review"] == 3


def test_overlay_null_removes_and_is_kept_as_none() -> None:
    kanban = next(b for b in PLAN_BLOCKS if "platform-kanban" in b)
    ov = load_document(kanban)
    assert isinstance(ov, WorkflowOverlay)
    assert ov.stages is not None
    assert ov.stages["refine"] is None
    assert ov.definition_of_done is None


# --- unknown and duplicate keys carry a line number -----------------------------------------


@pytest.mark.parametrize(
    ("anchor", "inject", "where"),
    [
        ("start: triage", "bonus: 1", "top"),
        ("    kind: wait\n    wait_for: human_answer", "    color: red", "stage"),
        ("      type: review", "      auto_approve: true", "gate"),
    ],
)
def test_unknown_key_fails_with_its_line(anchor: str, inject: str, where: str) -> None:
    lines = STANDARD.splitlines()
    idx = next(
        i for i, ln in enumerate(lines) if ln.strip() == anchor.strip().splitlines()[-1].strip()
    )
    indent = len(lines[idx]) - len(lines[idx].lstrip())
    lines.insert(idx + 1, " " * indent + inject.strip())
    text = "\n".join(lines) + "\n"
    err = _refused(text)
    key = inject.strip().split(":")[0]
    hit = [i for i in err.issues if key in i.message]
    assert hit, str(err)
    assert hit[0].line == idx + 2
    assert f"line {idx + 2}" in str(err)


def test_unknown_key_inside_next_edge_and_limits_and_timeouts() -> None:
    text = STANDARD.replace(
        "{ to: implement, loop: ci_fix }", "{ to: implement, loop: ci_fix, why: x }"
    )
    err = _refused(text)
    assert any("why" in i.message and i.line == _line_of(text, "why: x") for i in err.issues)
    text = STANDARD.replace("max_steps_per_run: 120", "max_steps_per_run: 120\n  max_cost: 4")
    err = _refused(text)
    assert any(i.line == _line_of(text, "max_cost") for i in err.issues)
    text = STANDARD.replace(
        "escalate_to: team_admin }", "escalate_to: team_admin, auto_approve_after: 3d }", 1
    )
    err = _refused(text)
    assert any(i.line == _line_of(text, "auto_approve_after") for i in err.issues)


def test_auto_approve_is_refused_and_explained() -> None:
    text = STANDARD.replace(
        "      type: review\n", "      type: review\n      auto_approve: true\n", 1
    )
    err = _refused(text)
    (issue,) = [i for i in err.issues if "auto_approve" in i.message]
    assert issue.line == _line_of(text, "auto_approve")
    assert "never approve" in issue.message
    assert "auto_approve" not in json.dumps(schema.json_schemas())


def test_duplicate_key_fails_with_the_second_line() -> None:
    text = STANDARD.replace("start: triage\n", "start: triage\nstart: refine\n", 1)
    err = _refused(text)
    (issue,) = err.issues
    assert issue.line == _line_of(text, "start: refine")
    assert "duplicate" in issue.message
    assert "start" in issue.message


def test_duplicate_key_nested_in_a_stage_and_in_a_flow_mapping() -> None:
    text = STANDARD.replace("    timeout: 2h\n", "    timeout: 2h\n    timeout: 9h\n", 1)
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, "timeout: 9h")
    text = STANDARD.replace("{ ready: refine,", "{ ready: refine, ready: plan,", 1)
    err = _refused(text)
    assert "duplicate" in err.issues[0].message
    assert err.issues[0].line == _line_of(text, "ready: refine, ready: plan")


def test_duplicate_stage_id_is_refused() -> None:
    text = STANDARD.replace(
        "  done: { kind: terminal, result: done }\n",
        "  done: { kind: terminal, result: done }\n  done: { kind: terminal, result: closed }\n",
    )
    err = _refused(text)
    assert "duplicate" in err.issues[0].message
    assert "done" in err.issues[0].message


# --- a bare `on` (and the other YAML 1.1 booleans) is refused --------------------------------


def test_bare_on_key_is_refused_with_an_explanation() -> None:
    text = STANDARD.replace(
        "    next: { resumed: { to: triage", "    on: { resumed: { to: triage", 1
    )
    err = _refused(text)
    (issue,) = err.issues
    assert issue.line == _line_of(text, "    on: { resumed")
    assert "next" in issue.message
    assert "boolean" in issue.message


@pytest.mark.parametrize("word", ["on", "On", "ON", "off", "yes", "No", "true", "False"])
def test_every_implicit_boolean_key_is_refused(word: str) -> None:
    text = STANDARD.replace("start: triage", f"{word}: x\nstart: triage")
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, f"{word}: x")
    assert "boolean" in err.issues[0].message


def test_quoted_on_is_a_string_and_is_accepted_as_a_route_value() -> None:
    text = STANDARD.replace(
        "next: { attested: push, default: pre_push_gate }",
        'next: { attested: push, "on": push, default: pre_push_gate }',
    )
    assert isinstance(load_document(text), Workflow)


@pytest.mark.parametrize("key", ["1", "~", "null", "2026-01-01", "1.5"])
def test_non_string_keys_are_refused(key: str) -> None:
    text = STANDARD.replace("start: triage", f"{key}: x\nstart: triage")
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, f"{key}: x")


# --- deleting or weakening a required gate does not pass silently ----------------------------


def _mutate(fn: Any) -> SchemaError:
    data = _std_data()
    fn(data["stages"])
    with pytest.raises(SchemaError) as info:
        load_document(yaml.safe_dump(data, sort_keys=False))
    return info.value


def test_a_gate_stage_without_its_gate_block_is_refused() -> None:
    err = _mutate(lambda s: s["review_gate"].pop("gate"))
    assert any("review_gate" in i.path and "gate" in i.path for i in err.issues)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eligible_roles", []),
        ("eligible_roles", "reviewer"),
        ("decisions", []),
        ("decisions", ["approve", "auto_approve"]),
        ("decision_surfaces", []),
        ("decision_surfaces", ["email"]),
        ("quorum", []),
        ("quorum", [{"role": "reviewer", "count": 0}]),
        ("quorum", [{"role": "reviewer"}]),
        ("carry_over", "always"),
        ("type", "auto"),
        ("separation_of_duties", {"not": []}),
        ("separation_of_duties", {"not": ["everyone"]}),
        ("separation_of_duties", {"not": [{"approver_of": ""}]}),
    ],
)
def test_weakened_gate_fields_are_refused(field: str, value: Any) -> None:
    err = _mutate(lambda s: s["review_gate"]["gate"].__setitem__(field, value))
    assert any(i.path.startswith("stages.review_gate.gate") for i in err.issues), str(err)


@pytest.mark.parametrize("field", ["eligible_roles", "decisions", "decision_surfaces"])
def test_gate_fields_that_must_be_stated_cannot_be_omitted(field: str) -> None:
    err = _mutate(lambda s: s["review_gate"]["gate"].pop(field))
    assert any(field in i.path or field in i.message for i in err.issues)


def test_requires_gates_may_not_be_emptied_or_nulled() -> None:
    err = _mutate(lambda s: s["merge"].__setitem__("requires_gates", []))
    assert any(i.path == "stages.merge.requires_gates" for i in err.issues)
    err = _mutate(lambda s: s["merge"].__setitem__("requires_gates", None))
    assert any(i.path == "stages.merge.requires_gates" and "null" in i.message for i in err.issues)


def test_null_in_a_full_workflow_is_refused_with_its_line() -> None:
    text = STANDARD.replace(
        "    requires_gates: [review_gate, qa_gate]\n    next: { done: merge }",
        "    requires_gates: null\n    next: { done: merge }",
    )
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, "requires_gates: null")
    assert "WorkflowOverlay" in err.issues[0].message


def test_null_stage_in_a_full_workflow_is_refused() -> None:
    err = _mutate(lambda s: s.__setitem__("review_gate", None))
    assert any(i.path == "stages.review_gate" for i in err.issues)


def test_stage_requires_its_kind_fields() -> None:
    err = _mutate(lambda s: s["merge"].pop("effect"))
    assert any(i.path == "stages.merge.effect" for i in err.issues)
    err = _mutate(lambda s: s["ci"].pop("source"))
    assert any(i.path == "stages.ci.source" for i in err.issues)
    err = _mutate(lambda s: s["llm_review"].pop("required"))
    assert any(i.path == "stages.llm_review.required" for i in err.issues)


@pytest.mark.parametrize(
    ("stage", "field", "value"),
    [
        ("llm_review", "required", []),
        ("llm_review", "reviewers", []),
        ("ci", "required", []),
        ("ci", "required", "anything"),
        ("ci", "timeout", "soon"),
        ("llm_review", "block_on", "none"),
        ("merge", "effect", "pr.force_push"),
        ("plan", "model_tier", "huge"),
        ("plan", "max_attempts", 0),
        ("triage", "next", {}),
    ],
)
def test_empty_floors_and_bad_values_are_refused(stage: str, field: str, value: Any) -> None:
    err = _mutate(lambda s: s[stage].__setitem__(field, value))
    assert any(i.path.startswith(f"stages.{stage}") for i in err.issues), str(err)


def test_team_default_is_the_only_string_for_required_checks() -> None:
    data = _std_data()
    assert data["stages"]["ci"]["required"] == "team_default"
    assert isinstance(load_document(yaml.safe_dump(data)), Workflow)


@pytest.mark.parametrize(
    ("stage", "outcome"),
    [
        ("ci", "approved"),
        ("review_gate", "green"),
        ("llm_review", "done"),
        ("merge", "clean"),
        ("await_info", "approved"),
    ],
)
def test_outcome_keys_are_closed_per_kind(stage: str, outcome: str) -> None:
    err = _mutate(lambda s: s[stage]["next"].__setitem__(outcome, "closed"))
    assert any(
        i.path.startswith(f"stages.{stage}.next") and outcome in i.message for i in err.issues
    )


def test_terminal_takes_no_next_and_other_kinds_need_one() -> None:
    err = _mutate(lambda s: s["done"].__setitem__("next", {"done": "closed"}))
    assert any(i.path.startswith("stages.done") for i in err.issues)
    err = _mutate(lambda s: s["merge"].pop("next"))
    assert any(i.path == "stages.merge.next" for i in err.issues)
    err = _mutate(lambda s: s["done"].pop("result"))
    assert any(i.path == "stages.done.result" for i in err.issues)


def test_unknown_kind_lists_the_valid_kinds() -> None:
    text = STANDARD.replace("kind: wait", "kind: sleep", 1)
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, "kind: sleep")
    assert "route" in err.issues[0].message


def test_with_is_the_wire_name_and_with_underscore_is_not() -> None:
    err = _mutate(lambda s: s["merge"].__setitem__("with_", {"method": "squash"}))
    assert any("with_" in i.message for i in err.issues)


# --- limits, durations and strictness --------------------------------------------------------


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("max_steps_per_run: 120", "max_steps_per_run: 501"),
        ("max_steps_per_run: 120", "max_steps_per_run: 0"),
        ("max_steps_per_run: 120", 'max_steps_per_run: "120"'),
        ("max_steps_per_run: 120", "max_steps_per_run: true"),
        ("max_run_age: 60d", "max_run_age: 301d"),
        ("max_run_age: 60d", "max_run_age: 8760h"),
        ("max_run_age: 60d", "max_run_age: forever"),
        ("max_run_age: 60d", "max_run_age: 60"),
        ("info: 2,", "info: 0,"),
        ("info: 2,", "info: -1,"),
        ("timeout: 10d", "timeout: 10 days"),
    ],
)
def test_limits_are_bounded_and_strictly_typed(old: str, new: str) -> None:
    err = _refused(STANDARD.replace(old, new, 1))
    assert err.issues


def test_platform_maximums_are_accepted_exactly() -> None:
    text = STANDARD.replace("max_steps_per_run: 120", "max_steps_per_run: 500").replace(
        "max_run_age: 60d", "max_run_age: 300d"
    )
    assert isinstance(load_document(text), Workflow)


def test_limits_are_required() -> None:
    data = _std_data()
    del data["limits"]["max_steps_per_run"]
    with pytest.raises(SchemaError):
        load_document(yaml.safe_dump(data))


def test_stage_and_loop_ids_must_be_identifiers() -> None:
    err = _refused(STANDARD.replace("  done: { kind: terminal", "  'Do Not': { kind: terminal", 1))
    assert err.issues


# --- document level --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("kind: Workflow\n", "apiVersion"),
        ("apiVersion: sto/v2\nkind: Workflow\n", "apiVersion"),
        ("apiVersion: sto/v1\n", "kind"),
        ("apiVersion: sto/v1\nkind: Pipeline\n", "kind"),
        ("- a\n- b\n", "mapping"),
        ("", "empty"),
        ("a: [1, 2\n", "yaml"),
        ("a: 1\n---\nb: 2\n", "one document"),
        ("apiVersion: &v sto/v1\nkind: Workflow\nx: *v\n", "alias"),
        ("apiVersion: sto/v1\nkind: Workflow\n<<: {a: 1}\n", "merge keys"),
    ],
)
def test_malformed_documents_are_refused(text: str, needle: str) -> None:
    err = _refused(text)
    assert needle.lower() in str(err).lower()


def test_syntax_error_has_a_line() -> None:
    err = _refused("apiVersion: sto/v1\nkind: Workflow\nmetadata: [oops\n")
    assert err.issues[0].line is not None


def test_error_text_lists_every_issue_with_line_and_path() -> None:
    text = STANDARD.replace("start: triage", "start: triage\nzzz: 1\nyyy: 2")
    err = _refused(text)
    assert len(err.issues) == 2
    rendered = str(err)
    assert f"line {_line_of(text, 'zzz')}" in rendered
    assert f"line {_line_of(text, 'yyy')}" in rendered


def test_load_accepts_a_source_name_in_messages() -> None:
    with pytest.raises(SchemaError) as info:
        load_document("kind: Workflow\n", source="wf.yaml")
    assert "wf.yaml" in str(info.value)


def test_models_are_frozen_and_reject_python_level_extras() -> None:
    wf = load_document(STANDARD)
    assert isinstance(wf, Workflow)
    with pytest.raises(Exception, match="frozen"):
        wf.start = "x"
    data = _std_data()
    data["surprise"] = 1
    with pytest.raises(Exception, match="surprise"):
        Workflow.model_validate(data)


def test_direct_validation_also_refuses_nulls() -> None:
    data = _std_data()
    data["stages"]["merge"]["requires_gates"] = None
    with pytest.raises(Exception, match="null"):
        Workflow.model_validate(data)


# --- overlays --------------------------------------------------------------------------------

OVERLAY = """\
apiVersion: sto/v1
kind: WorkflowOverlay
metadata: { name: o, team: t }
extends: standard@1
stages:
  review_gate:
    gate: { timeouts: { remind_after: 4h } }
  merge: null
"""


def test_overlay_parses_partial_stages() -> None:
    ov = load_document(OVERLAY)
    assert isinstance(ov, WorkflowOverlay)
    assert ov.extends == "standard@1"
    assert ov.stages is not None
    assert ov.stages["merge"] is None


@pytest.mark.parametrize(
    ("old", "new", "needle"),
    [
        (
            "    gate: { timeouts: { remind_after: 4h } }",
            "    gate: { timeouts: { remind_after: 4h, nap: 1h } }",
            "nap",
        ),
        (
            "    gate: { timeouts: { remind_after: 4h } }",
            "    gate: { auto_approve: true }",
            "auto_approve",
        ),
        (
            "    gate: { timeouts: { remind_after: 4h } }",
            "    gate: { eligible_roles: [] }",
            "eligible_roles",
        ),
        (
            "    gate: { timeouts: { remind_after: 4h } }",
            "    gate: { quorum: [{role: r, count: 0}] }",
            "quorum",
        ),
        ("extends: standard@1", "extends: standard", "extends"),
        ("  merge: null", "  merge: { requires_gates: [] }", "requires_gates"),
        ("  merge: null", "  merge: { bogus: 1 }", "bogus"),
        ("  merge: null", "  merge: { kind: sleep }", "kind"),
        ("  merge: null", "  merge: { next: { done: 3 } }", "next"),
    ],
)
def test_overlay_refusals(old: str, new: str, needle: str) -> None:
    text = OVERLAY.replace(old, new)
    err = _refused(text)
    assert any(needle in i.message or needle in i.path for i in err.issues), str(err)
    assert all(i.line is not None for i in err.issues)


def test_overlay_unknown_key_line() -> None:
    text = OVERLAY.replace("  merge: null", "  merge: { bogus: 1 }")
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, "bogus")


def test_overlay_requires_extends() -> None:
    err = _refused(OVERLAY.replace("extends: standard@1\n", ""))
    assert any("extends" in i.path for i in err.issues)


# --- TeamConfig and OrgPolicy ----------------------------------------------------------------


def _doc(kind: str) -> dict[str, Any]:
    block = next(b for b in PLAN_BLOCKS if f"kind: {kind}\n" in b)
    data = yaml.safe_load(block)
    assert isinstance(data, dict)
    return data


def _must_fail(data: dict[str, Any]) -> SchemaError:
    with pytest.raises(SchemaError) as info:
        load_document(yaml.safe_dump(data, sort_keys=False))
    return info.value


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["floors"]["mandatory_gate_roles"].__setitem__("review", ["developer"]),
        lambda d: d["floors"]["mandatory_gate_roles"].__setitem__("qa", []),
        lambda d: d["floors"]["mandatory_gate_roles"].__setitem__("mystery", ["qa"]),
        lambda d: d["floors"].__setitem__("surprise", True),
        lambda d: d["floors"].__setitem__("waive_allowed", "yes"),
        lambda d: d["floors"].__setitem__("hold_after_approval_min", "ten"),
        lambda d: d["floors"].__setitem__("single_human_allowed", None),
        lambda d: d["floors"].pop("identity_max_age"),
        lambda d: d["floors"]["decision_surfaces"].__setitem__("review", []),
        lambda d: d["floors"].__setitem__("requester_excluded_from", ["merge"]),
        lambda d: d["teams"]["ledger"]["required_gates"][0].pop("role"),
        lambda d: d["teams"]["ledger"]["required_gates"][1]["when"].pop("value"),
        lambda d: d["teams"]["ledger"].__setitem__("min_quorum", {"review": 0}),
        lambda d: d["teams"]["ledger"].__setitem__("allowed_carry_over", ["always"]),
        lambda d: d["teams"]["ledger"].__setitem__("auto_approve", True),
    ],
)
def test_org_policy_floors_cannot_be_weakened(edit: Any) -> None:
    data = _doc("OrgPolicy")
    edit(data)
    assert _must_fail(data).issues


def test_org_policy_defaults_are_the_safe_direction() -> None:
    data = _doc("OrgPolicy")
    for k in (
        "single_human_allowed",
        "waive_allowed",
        "public_repo_intake",
        "route_to_gate_allowed",
        "require_up_to_date",
    ):
        data["floors"].pop(k, None)
    pol = load_document(yaml.safe_dump(data))
    assert isinstance(pol, OrgPolicy)
    assert pol.floors.single_human_allowed is False
    assert pol.floors.public_repo_intake is False
    assert pol.floors.route_to_gate_allowed is False
    assert pol.floors.require_up_to_date is True


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["budgets"].pop("run_usd"),
        lambda d: d.pop("budgets"),
        lambda d: d["budgets"].__setitem__("run_usd", -1),
        lambda d: d["budgets"].__setitem__("run_usd", "forty"),
        lambda d: d["calendar"].__setitem__("workdays", ["mon", "someday"]),
        lambda d: d["calendar"].__setitem__("hours", "all day"),
        lambda d: d["sprint"].__setitem__("cadence", "5w"),
        lambda d: d["sprint"].__setitem__("anchor", "soon"),
        lambda d: d.__setitem__("wip_limit", 0),
        lambda d: d.__setitem__("surprise", 1),
        lambda d: d["custom_profiles"]["pci_reviewer"].pop("base"),
        lambda d: d["custom_profiles"]["pci_reviewer"].__setitem__("model", "x"),
        lambda d: d["qa"].__setitem__("test_domains", "*.example.com"),
    ],
)
def test_team_config_refusals(edit: Any) -> None:
    data = _doc("TeamConfig")
    edit(data)
    assert _must_fail(data).issues


def test_team_config_change_windows_use_from_and_to() -> None:
    data = _doc("TeamConfig")
    data["change_windows"] = {
        "deny": [
            {"from": "2026-12-24T00:00:00Z", "to": "2026-12-27T00:00:00Z", "reason": "holiday"}
        ],
        "allow_only": "0 9-17 * * 1-5",
    }
    cfg = load_document(yaml.safe_dump(data))
    assert isinstance(cfg, TeamConfig)
    assert cfg.change_windows is not None
    assert cfg.change_windows.deny[0].reason == "holiday"
    data["change_windows"]["deny"][0].pop("reason")
    assert _must_fail(data).issues


# --- the generated JSON Schema ---------------------------------------------------------------


def test_json_schemas_are_checked_in_and_current() -> None:
    generated = schema.json_schemas()
    assert set(generated) == {"workflow", "workflow-overlay", "team-config", "org-policy"}
    for name, doc in generated.items():
        path = ROOT / "schemas" / f"{name}.schema.json"
        assert path.exists(), f"missing {path}: run `uv run python -m sto.config.schema --write`"
        assert path.read_text(encoding="utf-8") == schema.render(doc), (
            f"{path} is stale: run `uv run python -m sto.config.schema --write`"
        )


def _objects(node: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if "properties" in node or "patternProperties" in node:
            out.append(node)
        for v in node.values():
            out.extend(_objects(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_objects(v))
    return out


def test_every_object_in_the_schema_refuses_unknown_keys() -> None:
    for name, doc in schema.json_schemas().items():
        objs = _objects(doc)
        assert objs, name
        for obj in objs:
            assert obj.get("additionalProperties") is False, (name, obj.get("title"))


def test_schema_stage_union_is_discriminated_and_closed() -> None:
    doc = schema.json_schemas()["workflow"]
    kinds = {
        d["properties"]["kind"]["const"]
        for d in doc["$defs"].values()
        if "kind" in d.get("properties", {}) and "const" in d["properties"]["kind"]
    }
    assert kinds >= {
        "agent",
        "review_panel",
        "checks",
        "gate",
        "effect",
        "wait",
        "route",
        "terminal",
    }
    gate = doc["$defs"]["Gate"]
    assert {"eligible_roles", "decisions", "decision_surfaces"} <= set(gate["required"])
    assert gate["properties"]["eligible_roles"]["minItems"] == 1
    assert "with" in doc["$defs"]["EffectStage"]["properties"]


def test_check_mode_reports_a_stale_file(tmp_path: Path) -> None:
    for name, doc in schema.json_schemas().items():
        (tmp_path / f"{name}.schema.json").write_text(schema.render(doc), encoding="utf-8")
    assert schema.main(["--check", "--dir", str(tmp_path)]) == 0
    (tmp_path / "workflow.schema.json").write_text("{}\n", encoding="utf-8")
    assert schema.main(["--check", "--dir", str(tmp_path)]) == 1
    assert schema.main(["--write", "--dir", str(tmp_path)]) == 0
    assert schema.main(["--check", "--dir", str(tmp_path)]) == 0


def test_a_gate_without_carry_over_gets_none_not_patch_id() -> None:
    data = _std_data()
    del data["stages"]["review_gate"]["gate"]["carry_over"]
    wf = load_document(yaml.safe_dump(data))
    assert isinstance(wf, Workflow)
    assert wf.stages["review_gate"].gate.carry_over == "none"  # type: ignore[union-attr]


@pytest.mark.parametrize("result", ["finished", "approved", 1])
def test_terminal_results_are_a_closed_set(result: object) -> None:
    err = _mutate(lambda s: s["done"].__setitem__("result", result))
    assert any(i.path == "stages.done.result" for i in err.issues)


@pytest.mark.parametrize("value", ["1d", "90m", "2w", "30s", "300d"])
def test_durations_accept_one_number_and_one_unit(value: str) -> None:
    assert schema.duration_seconds(value) > 0


@pytest.mark.parametrize("value", ["", "0d", "d", "1.5h", "1d2h", "10 days", " 1d", "-1d", "1y"])
def test_durations_refuse_everything_else(value: str) -> None:
    with pytest.raises(ValueError, match="duration"):
        schema.duration_seconds(value)


def test_full_document_schemas_allow_no_null_but_the_overlay_does() -> None:
    schemas = schema.json_schemas()
    for name in ("workflow", "team-config", "org-policy"):
        assert '{"type": "null"}' not in json.dumps(schemas[name], sort_keys=True), name
    assert '{"type": "null"}' in json.dumps(schemas["workflow-overlay"], sort_keys=True)


# =============================================================================================
# Review pass 1
# =============================================================================================

MIN = (
    "apiVersion: sto/v1\nkind: Workflow\nmetadata: {name: a, team: t}\n"
    "limits: {max_steps_per_run: 5, max_run_age: 1d}\nstart: e\nstages:\n"
    "  e: {kind: terminal, result: done}\n"
)
TEAM = next(b for b in PLAN_BLOCKS if "kind: TeamConfig\n" in b)
ORG = next(b for b in PLAN_BLOCKS if "kind: OrgPolicy\n" in b)
REG = next(b for b in PLAN_BLOCKS if "ledger-regulated" in b)
OVERLAYS = [b for b in PLAN_BLOCKS if "kind: WorkflowOverlay\n" in b]


def _effect_doc(effect: str, nexts: str) -> str:
    return MIN.replace(
        "  e: {kind: terminal, result: done}\n",
        f"  e: {{kind: terminal, result: done}}\n"
        f"  x: {{kind: effect, effect: {effect}, next: {{{nexts}}}}}\n",
    )


# --- 1. load_document raises SchemaError and nothing else -------------------------------------


@pytest.mark.parametrize(
    ("label", "text", "line"),
    [
        ("invalid anchor date", TEAM.replace("2026-11-02", "2026-02-30"), None),
        ("month 13 date", MIN + "zzz: 2026-13-45\n", 8),
        (
            "invalid instant",
            TEAM
            + "change_windows: {deny: [{from: 2026-13-45 10:00:00, to: 2026-12-27, reason: x}]}\n",
            None,
        ),
        ("huge integer", MIN + "zzz: " + "1" * 5000 + "\n", 8),
        ("huge limit", MIN.replace("max_steps_per_run: 5", "max_steps_per_run: " + "1" * 5000), 4),
        ("NUL", MIN + "# \x00\n", 8),
        ("control character", MIN + "zzz: \x07\n", 8),
        ("complex sequence key", MIN + "? [a, b]\n: c\n", 8),
        ("complex mapping key", MIN + "? {a: 1}\n: c\n", 8),
        ("tagged sequence key", MIN + "? !!str [a]\n: c\n", 8),
        ("deep sequence", MIN + "zzz: " + "[" * 3000 + "]" * 3000 + "\n", 8),
        ("deep mapping", MIN + "zzz: " + "{a: " * 2000 + "1" + "}" * 2000 + "\n", 8),
        (
            "deep with",
            MIN.replace(
                "  e: {kind: terminal, result: done}",
                "  e: {kind: effect, effect: notify, with: {a: "
                + "[" * 800
                + "]" * 800
                + "}, next: {done: e}}",
            ),
            7,
        ),
    ],
)
def test_nothing_but_schema_error_escapes_the_loader(
    label: str, text: str, line: int | None
) -> None:
    err = _refused(text)
    assert err.issues, label
    if line is not None:
        assert err.issues[0].line == line, (label, str(err))
    assert all(i.line is not None for i in err.issues), (label, str(err))


def test_the_invalid_date_is_reported_on_its_own_line() -> None:
    text = TEAM.replace("2026-11-02", "2026-02-30")
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, "2026-02-30")


@pytest.mark.parametrize(
    ("payload", "needle", "line"),
    [
        (b"apiVersion: sto/v1\nx: \xff\xfe\n", "utf-8", 2),
        ("a: 1\n".encode("utf-16"), "utf-8", 1),
    ],
)
def test_bad_bytes_are_a_schema_error(payload: bytes, needle: str, line: int) -> None:
    with pytest.raises(SchemaError) as info:
        load_document(payload)
    assert needle in str(info.value).lower()
    assert info.value.issues[0].line == line


def test_bytes_and_text_load_alike() -> None:
    assert load_document(MIN.encode()) == load_document(MIN)


def test_nesting_limit_is_exactly_max_depth() -> None:
    def doc(levels: int) -> str:
        return MIN + "zzz: " + "[" * levels + "]" * levels + "\n"

    ok = _refused(doc(schema.MAX_DEPTH - 1))  # the root mapping is level 1
    assert "nesting" not in str(ok)
    too_deep = _refused(doc(schema.MAX_DEPTH))
    assert "nesting" in str(too_deep)
    assert too_deep.issues[0].line == 8


def test_with_values_are_depth_limited_for_programmatic_use_too() -> None:
    deep: Any = 1
    for _ in range(schema.MAX_DEPTH + 5):
        deep = [deep]
    data = _std_data()
    data["stages"]["merge"]["with"] = {"a": deep}
    with pytest.raises(Exception, match="nesting"):
        Workflow.model_validate(data)


# --- 2. no infinity and no NaN ----------------------------------------------------------------


@pytest.mark.parametrize("value", [".inf", "-.inf", ".Inf", ".nan", ".NaN", "1.0e+400", "1e999"])
@pytest.mark.parametrize("field", ["run_usd", "team_monthly_usd"])
def test_budgets_refuse_infinity_and_nan(field: str, value: str) -> None:
    text = TEAM.replace(f"{field}: {'40' if field == 'run_usd' else '3000'}", f"{field}: {value}")
    assert text != TEAM
    _refused(text)


@pytest.mark.parametrize("value", [".inf", "1.0e+400", ".nan"])
def test_stage_budget_and_dod_refuse_infinity_and_nan(value: str) -> None:
    _refused(TEAM.replace("implement: 20", f"implement: {value}"))
    _refused(
        STANDARD.replace(
            "  - { stage: review_gate, check: checks_green }",
            f"  - {{ stage: review_gate, check: coverage_at_least, value: {value} }}",
        )
    )


def test_budgets_refuse_infinity_when_built_in_python() -> None:
    for bad in (float("inf"), float("nan"), -float("inf")):
        data = yaml.safe_load(TEAM)
        data["budgets"]["run_usd"] = bad
        with pytest.raises(Exception, match="finite"):
            TeamConfig.model_validate(data)


@pytest.mark.parametrize("block", PLAN_BLOCKS, ids=_block_id)
def test_every_plan_document_dumps_and_reloads_to_the_same_model(block: str) -> None:
    doc = load_document(block)
    # Full documents dump without their unset (None) fields; an overlay's own dump already does.
    opts: dict[str, Any] = {} if isinstance(doc, WorkflowOverlay) else {"exclude_none": True}
    dumped = doc.model_dump_json(by_alias=True, **opts)
    assert "NaN" not in dumped
    assert "Infinity" not in dumped
    again = type(doc).model_validate_json(dumped, strict=False)
    assert again == doc


# --- 3. line numbers in an overlay stage that states kind: gate -------------------------------


def _reg_with_auto_approve(drop_kind: bool) -> str:
    text = REG.replace(
        "      type: custom\n      eligible_roles: [security_officer]",
        "      type: custom\n      auto_approve: true\n      eligible_roles: [security_officer]",
        1,
    )
    if drop_kind:
        text = text.replace("  security_gate:\n    kind: gate\n", "  security_gate:\n", 1)
    return text


@pytest.mark.parametrize("drop_kind", [False, True], ids=["with-kind", "without-kind"])
def test_overlay_gate_errors_name_the_gate_path_and_line_with_or_without_kind(
    drop_kind: bool,
) -> None:
    text = _reg_with_auto_approve(drop_kind)
    err = _refused(text)
    (issue,) = err.issues
    assert issue.line == _line_of(text, "auto_approve")
    assert issue.path == "stages.security_gate.gate.auto_approve"


def test_a_workflow_stage_whose_field_shares_its_kind_name_keeps_its_path() -> None:
    text = STANDARD.replace("      type: review\n", "      type: review\n      nope: 1\n", 1)
    (issue,) = _refused(text).issues
    assert issue.path == "stages.review_gate.gate.nope"
    assert issue.line == _line_of(text, "nope: 1")
    text = STANDARD.replace("effect: branch.push,", "effect: branch.push, nope: 1,", 1)
    (issue,) = _refused(text).issues
    assert issue.path == "stages.push.nope"


def test_overlay_effect_field_errors_keep_their_path_too() -> None:
    text = OVERLAY.replace("  merge: null", "  merge: { kind: effect, effect: pr.merge, zap: 1 }")
    (issue,) = _refused(text).issues
    assert issue.path == "stages.merge.zap"


# --- 4. only core tags and JSON values --------------------------------------------------------


def _with_value(raw: str) -> str:
    return MIN.replace(
        "  e: {kind: terminal, result: done}",
        "  e: {kind: effect, effect: notify, with: {a: " + raw + "}, next: {done: e}}",
    )


@pytest.mark.parametrize(
    "raw",
    [
        "!!set {x, y}",
        "!!binary aGk=",
        "!!omap [on: 1]",
        "!!omap [on: 1, on: 2]",
        "!!pairs [auto_approve: 1, auto_approve: 2]",
        "!!python/object/apply:os.getpid []",
        "!!python/name:os.system",
        "!foo bar",
        "2026-01-01",
        "2026-01-01 10:00:00",
    ],
)
def test_tags_and_values_json_cannot_hold_are_refused(raw: str) -> None:
    err = _refused(_with_value(raw))
    assert err.issues[0].line is not None


@pytest.mark.parametrize(
    "text",
    [
        MIN + "zzz: !!python/object/apply:os.getpid []\n",
        MIN + "? !!python/name:os.system\n: 1\n",
        "%TAG !p! tag:yaml.org,2002:python/\n---\nzz: !p!object/apply:os.getpid []\n",
        MIN + "zzz: !!set {a}\n",
        MIN + "zzz: !!binary aGk=\n",
    ],
)
def test_python_and_other_non_core_tags_never_construct_anything(text: str) -> None:
    err = _refused(text)
    assert "tag" in str(err).lower()


def test_core_tags_still_work() -> None:
    text = MIN.replace("result: done", "result: !!str done").replace(
        "max_steps_per_run: 5", "max_steps_per_run: !!int 5"
    )
    assert isinstance(load_document(text), Workflow)


@pytest.mark.parametrize("raw", ["!!int 0x10", "!!int 010", "!!float 0x1", "!!int 1:00"])
def test_explicit_number_tags_do_not_bring_back_yaml_1_1_forms(raw: str) -> None:
    _refused(MIN.replace("max_steps_per_run: 5", f"max_steps_per_run: {raw}"))


def test_with_holds_only_json_data_and_is_frozen() -> None:
    wf = load_document(STANDARD)
    assert isinstance(wf, Workflow)
    merge = wf.stages["merge"]
    assert isinstance(merge, schema.EffectStage)
    assert merge.with_ is not None
    assert dict(merge.with_) == {"method": "squash"}
    text = _with_value("{b: [1, 2.5, true, x, {c: 1}]}")
    loaded = load_document(text)
    assert isinstance(loaded, Workflow)
    stage = loaded.stages["e"]
    assert isinstance(stage, schema.EffectStage)
    assert stage.with_ is not None
    json.dumps(stage.model_dump(mode="json"))  # only JSON-able data
    nested = stage.with_["a"]["b"]
    assert isinstance(nested, tuple)
    with pytest.raises(TypeError):
        nested[4]["c"] = 2


# --- 5. deep immutability ---------------------------------------------------------------------


def _assert_no_mutable_containers(node: Any, where: str = "") -> None:
    assert not isinstance(node, list | dict | set), f"mutable {type(node).__name__} at {where}"
    if isinstance(node, BaseModel):
        for name in type(node).model_fields:
            _assert_no_mutable_containers(getattr(node, name), f"{where}.{name}")
    elif isinstance(node, tuple):
        for i, v in enumerate(node):
            _assert_no_mutable_containers(v, f"{where}[{i}]")
    elif isinstance(node, Mapping):
        for k, v in node.items():
            _assert_no_mutable_containers(v, f"{where}[{k!r}]")


@pytest.mark.parametrize("block", PLAN_BLOCKS, ids=_block_id)
def test_loaded_documents_hold_no_list_dict_or_set_anywhere(block: str) -> None:
    _assert_no_mutable_containers(load_document(block))


def test_defaults_are_immutable_too() -> None:
    wf = load_document(MIN)
    assert isinstance(wf, Workflow)
    _assert_no_mutable_containers(wf)
    org = load_document(
        "apiVersion: sto/v1\nkind: OrgPolicy\nfloors:\n"
        "  mandatory_gate_roles: {pre_push: [reviewer], review: [reviewer], qa: [qa]}\n"
        "  decision_surfaces: {review: [ui]}\n  hold_after_approval_min: 10m\n"
        "  identity_max_age: 8h\n"
    )
    _assert_no_mutable_containers(org)


def test_nested_collections_cannot_be_changed() -> None:
    wf = load_document(STANDARD)
    assert isinstance(wf, Workflow)
    gate_stage = wf.stages["review_gate"]
    assert isinstance(gate_stage, schema.GateStage)
    with pytest.raises(AttributeError):
        gate_stage.gate.eligible_roles.append("developer")  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        wf.stages["review_gate"] = gate_stage  # type: ignore[index]
    with pytest.raises(AttributeError):
        wf.stages.pop("review_gate")  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        del wf.stages["review_gate"]  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        wf.limits.loops["x"] = 1  # type: ignore[index]
    merge = wf.stages["merge"]
    assert isinstance(merge, schema.EffectStage)
    assert merge.requires_gates is not None
    with pytest.raises(AttributeError):
        merge.requires_gates.clear()  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        merge.next["done"] = "closed"  # type: ignore[index]
    with pytest.raises(Exception, match="frozen"):
        gate_stage.gate.carry_over = "none"
    assert len(wf.stages["review_gate"].gate.eligible_roles) == 1  # type: ignore[union-attr]


def test_team_and_org_documents_are_deeply_immutable_too() -> None:
    team = load_document(TEAM)
    assert isinstance(team, TeamConfig)
    assert team.budgets.stage_usd is not None
    with pytest.raises(TypeError):
        team.budgets.stage_usd["implement"] = 0.01  # type: ignore[index]
    assert team.calendar is not None
    with pytest.raises(AttributeError):
        team.calendar.workdays.append("sat")  # type: ignore[attr-defined]
    org = load_document(ORG)
    assert isinstance(org, OrgPolicy)
    with pytest.raises(AttributeError):
        org.floors.mandatory_gate_roles["review"].append("developer")  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        org.floors.mandatory_gate_roles["qa"] = ("x",)  # type: ignore[index]


def test_overlay_patches_are_deeply_immutable() -> None:
    ov = load_document(OVERLAY)
    assert isinstance(ov, WorkflowOverlay)
    assert ov.stages is not None
    with pytest.raises(TypeError):
        ov.stages["merge"] = None  # type: ignore[index]
    with pytest.raises(Exception, match="frozen"):
        ov.extends = "other@1"
    patch = ov.stages["review_gate"]
    assert patch is not None
    with pytest.raises(Exception, match="frozen"):
        patch.timeout = "1d"


# --- 6. field values --------------------------------------------------------------------------


def _team_with(window: str) -> str:
    return TEAM + f"change_windows: {{deny: [{window}]}}\n"


@pytest.mark.parametrize(
    "window",
    [
        "{from: 2026-12-27T00:00:00Z, to: 2026-12-24T00:00:00Z, reason: x}",
        "{from: 2026-12-24T00:00:00Z, to: 2026-12-24T00:00:00Z, reason: x}",
        "{from: 2026-12-24T00:00:00+01:00, to: 2026-12-23T22:30:00Z, reason: x}",
        "{from: 1, to: 2026-12-27T00:00:00Z, reason: x}",
        "{from: 2026-12-24T00:00:00Z, to: 1767225600, reason: x}",
        "{from: 2026-12-24 10:00:00, to: 2026-12-24 12:00:00, reason: x}",
        "{from: 2026-12-24, to: 2026-12-27, reason: x}",
        "{from: '2026-12-24T10:00:00', to: '2026-12-24T12:00:00', reason: x}",
        "{from: true, to: 2026-12-27T00:00:00Z, reason: x}",
        "{from: 2026-12-24T00:00:00Z, to: 2026-12-27T00:00:00Z, reason: ' '}",
    ],
)
def test_deny_windows_need_aware_instants_in_order(window: str) -> None:
    err = _refused(_team_with(window))
    assert all(i.line is not None for i in err.issues)


@pytest.mark.parametrize(
    "window",
    [
        "{from: 2026-12-24T00:00:00Z, to: 2026-12-27T00:00:00Z, reason: x}",
        "{from: 2026-12-24T00:00:00+01:00, to: 2026-12-27 00:00:00 -05:00, reason: x}",
        "{from: '2026-12-24T00:00:00Z', to: '2026-12-27T00:00:00+00:00', reason: x}",
    ],
)
def test_deny_windows_accept_aware_instants(window: str) -> None:
    cfg = load_document(_team_with(window))
    assert isinstance(cfg, TeamConfig)
    assert cfg.change_windows is not None
    first = cfg.change_windows.deny[0]
    assert first.from_.utcoffset() is not None
    assert first.from_ < first.to


@pytest.mark.parametrize(
    "hours",
    [
        "29:00-25:59",
        "9:00-17:00",
        "09:00-17:60",
        "09:00",
        "17:30-09:00",
        "09:00-09:00",
        "24:00-25:00",
        "all day",
    ],
)
def test_hours_must_be_a_real_ascending_range(hours: str) -> None:
    _refused(TEAM.replace("09:00-17:30", hours))


def test_hours_accept_a_real_range() -> None:
    cfg = load_document(TEAM.replace("09:00-17:30", "00:00-23:59"))
    assert isinstance(cfg, TeamConfig)


@pytest.mark.parametrize(
    "tz", ["Mars/Phobos", "../../etc/passwd", "europe/london", "Europe/", "", " "]
)
def test_unknown_timezones_are_refused(tz: str) -> None:
    _refused(TEAM.replace("Europe/London", f"'{tz}'"))


@pytest.mark.parametrize("tz", ["Europe/London", "UTC", "America/New_York", "Asia/Kolkata"])
def test_iana_timezones_are_accepted(tz: str) -> None:
    assert isinstance(load_document(TEAM.replace("Europe/London", tz)), TeamConfig)


def test_repeated_workdays_are_refused() -> None:
    _refused(TEAM.replace("[mon, tue, wed, thu, fri]", "[mon, mon]"))


_REPO = "repo: { name: example/payments, base: main, sandbox_image: java21 }"


@pytest.mark.parametrize(
    "base",
    [
        "-x",
        "--upload-pack=x",
        "a..b",
        "a//b",
        "main/",
        "x.lock",
        "a/b.lock",
        ".hidden",
        "a/.hidden",
        "a b",
        "a~1",
        "a^",
        "a:b",
        "a?b",
        "a*b",
        "a[b",
        "a\\b",
        "main.",
        "",
        "@{u}",
    ],
)
def test_repo_base_must_be_a_valid_branch_name(base: str) -> None:
    text = OVERLAYS[0].replace(
        _REPO, f"repo: {{ name: example/payments, base: '{base}', sandbox_image: java21 }}"
    )
    assert text != OVERLAYS[0]
    err = _refused(text)
    assert any(i.path == "repo.base" for i in err.issues)


@pytest.mark.parametrize("base", ["main", "release/1.2", "feature/x-1_y", "v1.0.0", "a.b"])
def test_repo_base_accepts_ordinary_branch_names(base: str) -> None:
    text = OVERLAYS[0].replace(
        _REPO, f"repo: {{ name: example/payments, base: '{base}', sandbox_image: java21 }}"
    )
    assert isinstance(load_document(text), WorkflowOverlay)


@pytest.mark.parametrize(
    "name",
    [
        "../..",
        "a/..",
        "../b",
        "./b",
        "a/.",
        "-a/b",
        "a/-b",
        "a/b/c",
        "a",
        "a b/c",
        "a/b\n",
        "/b",
        "a/",
    ],
)
def test_repo_name_cannot_traverse_or_start_with_a_dash(name: str) -> None:
    text = OVERLAYS[0].replace(
        _REPO, f"repo: {{ name: '{name}', base: main, sandbox_image: java21 }}"
    )
    err = _refused(text)
    assert any(i.path == "repo.name" for i in err.issues)


@pytest.mark.parametrize("name", ["example/payments", "a_b/c.d-e", "A1/b2"])
def test_repo_name_accepts_owner_slash_name(name: str) -> None:
    text = OVERLAYS[0].replace(
        _REPO, f"repo: {{ name: '{name}', base: main, sandbox_image: java21 }}"
    )
    assert isinstance(load_document(text), WorkflowOverlay)


_MGR = "mandatory_gate_roles: { pre_push: [reviewer], review: [reviewer], qa: [qa, reviewer] }"


@pytest.mark.parametrize(
    "roles",
    [
        "{}",
        "{ pre_push: [reviewer] }",
        "{ pre_push: [reviewer], review: [reviewer] }",
        "{ review: [reviewer], qa: [qa] }",
        "{ pre_push: [reviewer], review: [reviewer], qa: [] }",
    ],
)
def test_every_mandatory_gate_must_name_roles(roles: str) -> None:
    err = _refused(ORG.replace(_MGR, f"mandatory_gate_roles: {roles}"))
    assert any("mandatory_gate_roles" in i.path for i in err.issues)


@pytest.mark.parametrize("gate", ["pre_push", "review", "qa"])
def test_developer_is_refused_on_every_mandatory_gate(gate: str) -> None:
    roles = {"pre_push": "[reviewer]", "review": "[reviewer]", "qa": "[qa]"}
    roles[gate] = "[reviewer, developer]"
    inner = ", ".join(f"{k}: {v}" for k, v in roles.items())
    err = _refused(ORG.replace(_MGR, f"mandatory_gate_roles: {{ {inner} }}"))
    assert any("developer" in i.message for i in err.issues)


def test_org_policy_defaults_are_exactly_the_safe_ones() -> None:
    minimal = (
        "apiVersion: sto/v1\nkind: OrgPolicy\nfloors:\n"
        "  mandatory_gate_roles: {pre_push: [reviewer], review: [reviewer], qa: [qa]}\n"
        "  decision_surfaces: {review: [ui]}\n  hold_after_approval_min: 10m\n"
        "  identity_max_age: 8h\n"
    )
    pol = load_document(minimal)
    assert isinstance(pol, OrgPolicy)
    f = pol.floors
    assert f.single_human_allowed is False
    assert f.waive_allowed is False
    assert f.public_repo_intake is False
    assert f.route_to_gate_allowed is False
    assert f.require_up_to_date is True
    assert f.requester_excluded_from == ("review", "pre_push")
    assert f.require_up_to_date_waived_for == ()
    assert f.ci_without_secrets_waived_for == ()
    assert dict(pol.teams) == {}


@pytest.mark.parametrize(
    "number", ["1:00", "010", "0x10", "0b11", "0o10", "1_0", "+5", "5.0", "1e1"]
)
def test_yaml_1_1_number_forms_are_not_a_plain_int(number: str) -> None:
    text = STANDARD.replace(
        "      type: review\n",
        f"      type: review\n      quorum: [{{role: reviewer, count: {number}}}]\n",
        1,
    )
    err = _refused(text)
    assert any(i.path.endswith("count") for i in err.issues)
    _refused(MIN.replace("max_steps_per_run: 5", f"max_steps_per_run: {number}"))


@pytest.mark.parametrize("number", ["1:00", "010", "0x10", "0b11", "1_0", "+5"])
def test_yaml_1_1_number_forms_are_not_a_plain_float_either(number: str) -> None:
    _refused(TEAM.replace("run_usd: 40", f"run_usd: {number}"))


def test_plain_numbers_still_load() -> None:
    cfg = load_document(
        TEAM.replace("run_usd: 40", "run_usd: 1.5e1").replace(
            "team_monthly_usd: 3000", "team_monthly_usd: 0.5"
        )
    )
    assert isinstance(cfg, TeamConfig)
    assert cfg.budgets.run_usd == 15.0
    assert cfg.budgets.team_monthly_usd == 0.5


@pytest.mark.parametrize(
    "anchor",
    [
        "0",
        "1730505600",
        "20261102",
        "true",
        "2026-11-02 10:00:00",
        "'11/02/2026'",
        "'2026-02-30'",
        "'2026-11-02T00:00:00Z'",
    ],
)
def test_sprint_anchor_must_be_a_real_date(anchor: str) -> None:
    _refused(TEAM.replace("2026-11-02", anchor))


@pytest.mark.parametrize("anchor", ["2026-11-02", "'2026-11-02'"])
def test_sprint_anchor_accepts_a_date(anchor: str) -> None:
    cfg = load_document(TEAM.replace("2026-11-02", anchor))
    assert isinstance(cfg, TeamConfig)
    assert cfg.sprint is not None
    assert cfg.sprint.anchor == dt.date(2026, 11, 2)
    assert not isinstance(cfg.sprint.anchor, dt.datetime)


def test_a_newline_in_a_key_cannot_forge_a_line_in_an_error() -> None:
    text = MIN.replace(
        "  e: {kind: terminal, result: done}",
        "  e: {kind: terminal, result: done}\n"
        '  "x\\nline 1: everything: fine": {kind: terminal, result: done}',
    )
    err = _refused(text)
    rendered = str(err)
    assert len(rendered.splitlines()) == len(err.issues)
    assert "\n" not in err.issues[0].path
    assert "\\n" in rendered


def test_other_control_characters_in_keys_are_escaped() -> None:
    err = _refused('apiVersion: sto/v1\nkind: Workflow\n"\\e[2J\\e[32mok": 1\n')
    assert "\x1b" not in str(err)
    long_key = _refused(MIN + "? " + "k" * 20000 + "\n: 1\n")
    assert len(str(long_key)) < 2000
    assert "..." in str(long_key)


def test_a_hostile_source_name_cannot_forge_lines_either() -> None:
    with pytest.raises(SchemaError) as info:
        load_document("kind: Workflow\n", source="a\nb.yaml")
    assert "\n" not in info.value.source
    assert len(str(info.value).splitlines()) == len(info.value.issues)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("approved: promote", 'approved: "Bad Id"'),
        (
            "changes_requested: { to: implement, loop: human_review }",
            "changes_requested: { to: Bad, loop: human_review }",
        ),
        (
            "changes_requested: { to: implement, loop: human_review }",
            "changes_requested: { to: implement, loop: Bad }",
        ),
        ("  triage: {", "  'Bad Id': {"),
        ("loops: { info: 2,", "loops: { Bad: 2,"),
        ("eligible_roles: [reviewer]", "eligible_roles: [Reviewer]"),
        ("escalate_to: team_admin", "escalate_to: Team"),
        ("timeout: 2h", "timeout: 2 hours"),
        ("max_steps_per_run: 120", "max_steps_per_run: 0"),
        ("next: { ready: refine,", "next: { 'bad key!': refine, ready: refine,"),
    ],
)
def test_internal_validator_labels_never_leak_into_errors(old: str, new: str) -> None:
    text = STANDARD.replace(old, new, 1)
    assert text != STANDARD
    err = _refused(text)
    for issue in err.issues:
        blob = f"{issue.path} {issue.message}"
        for label in ("constrained", "[key]", "function-", "lax-or-strict", "json-or-python"):
            assert label not in blob, (label, str(err))
    assert any(i.line is not None for i in err.issues)


def test_a_bad_dict_key_points_at_the_key_itself() -> None:
    text = STANDARD.replace("  triage: {", "  'Bad Id': {", 1)
    err = _refused(text)
    assert any(i.path == "stages.Bad Id" and i.line == _line_of(text, "Bad Id") for i in err.issues)


# --- 7. overlay dumps cannot turn an unset field into a removal --------------------------------


@pytest.mark.parametrize("block", OVERLAYS, ids=_block_id)
def test_overlay_to_patch_round_trips_the_document_exactly(block: str) -> None:
    ov = load_document(block)
    assert isinstance(ov, WorkflowOverlay)
    raw = yaml.safe_load(block)
    body = {k: v for k, v in raw.items() if k not in schema.OVERLAY_HEAD_KEYS}
    assert ov.to_patch() == body
    assert not set(ov.to_patch()) & set(schema.OVERLAY_HEAD_KEYS)
    assert "apiVersion" in ov.model_dump(by_alias=True)  # the plain dump keeps the head


@pytest.mark.parametrize("block", OVERLAYS, ids=_block_id)
def test_overlay_plain_dumps_leave_unset_fields_out(block: str) -> None:
    ov = load_document(block)
    assert isinstance(ov, WorkflowOverlay)
    dumped = ov.model_dump(mode="json", by_alias=True)
    raw = yaml.safe_load(block)
    assert dumped == raw
    assert json.loads(ov.model_dump_json(by_alias=True)) == raw
    assert dumped.get("start", "absent") == "absent"  # unset, so not null


def test_an_explicit_null_survives_the_dump_and_an_unset_field_does_not() -> None:
    ov = load_document(OVERLAY)
    assert isinstance(ov, WorkflowOverlay)
    dumped = ov.model_dump()
    assert dumped["stages"]["merge"] is None
    assert "timeout" not in dumped["stages"]["review_gate"]
    assert "intake" not in dumped
    assert ov.stages is not None
    assert ov.stages["review_gate"] is not None
    assert ov.stages["review_gate"].model_dump() == {"gate": {"timeouts": {"remind_after": "4h"}}}


def test_the_unsafe_dump_is_available_only_by_asking_for_it() -> None:
    ov = load_document(OVERLAY)
    assert isinstance(ov, WorkflowOverlay)
    loud = ov.model_dump(exclude_unset=False)
    assert loud["intake"] is None


@pytest.mark.parametrize("block", OVERLAYS, ids=_block_id)
def test_a_dumped_overlay_reloads_to_an_equal_overlay(block: str) -> None:
    ov = load_document(block)
    assert isinstance(ov, WorkflowOverlay)
    head = {k: v for k, v in yaml.safe_load(block).items() if k in schema.OVERLAY_HEAD_KEYS}
    again = load_document(yaml.safe_dump({**head, **ov.to_patch()}))
    assert again == ov


# --- not here: kept out on purpose (see PR) ---------------------------------------------------


def test_semantic_rules_stay_out_of_this_layer() -> None:
    """Rulings: these belong to V4, V10, D2-03 and D2-02, so the schema must still accept them."""
    # merge with no requires_gates (V4, D2-04)
    text = STANDARD.replace(
        "    with: { method: squash }\n    requires_gates: [review_gate, qa_gate]\n",
        "    with: { method: squash }\n",
    )
    assert isinstance(load_document(text), Workflow)
    # decisions: [waive] (V10, D2-03)
    text = STANDARD.replace(
        "decisions: [approve, request_changes, reject]", "decisions: [waive]", 1
    )
    assert isinstance(load_document(text), Workflow)
    # a quorum role that is not eligible (D2-03)
    text = STANDARD.replace(
        "      type: review\n", "      type: review\n      quorum: [{role: nobody, count: 1}]\n", 1
    )
    assert isinstance(load_document(text), Workflow)
    # with: {auto_approve: true} on pr.merge (typed `with`, D2-03/D2-18)
    text = STANDARD.replace("with: { method: squash }", "with: { auto_approve: true }")
    assert isinstance(load_document(text), Workflow)
    # unbounded stage durations (D2-03)
    text = STANDARD.replace("timeout: 2h", "timeout: 9999w", 1)
    assert isinstance(load_document(text), Workflow)


# --- killing the surviving mutants -----------------------------------------------------------


@pytest.mark.parametrize(
    ("location", "edit"),
    [
        ("eligible_roles", lambda g: g.__setitem__("eligible_roles", ["review er"])),
        ("eligible_roles", lambda g: g.__setitem__("eligible_roles", ["reviewer!"])),
        ("eligible_roles", lambda g: g.__setitem__("eligible_roles", ["Reviewer"])),
        ("quorum", lambda g: g.__setitem__("quorum", [{"role": "Rev", "count": 1}])),
        ("quorum", lambda g: g.__setitem__("quorum", [{"role": "rev!", "count": 1}])),
        ("quorum", lambda g: g.__setitem__("quorum", [{"role": 7, "count": 1}])),
        ("timeouts", lambda g: g["timeouts"].__setitem__("escalate_to", "Team Admin")),
        ("timeouts", lambda g: g["timeouts"].__setitem__("escalate_to", "team_admin!")),
        ("timeouts", lambda g: g["timeouts"].__setitem__("remind_after", "1dx")),
        ("timeouts", lambda g: g["timeouts"].__setitem__("escalate_after", "soon")),
        ("timeouts", lambda g: g["timeouts"].__setitem__("expire_after", "1d2h")),
        ("path_owners", lambda g: g.__setitem__("path_owners", "everyone")),
        (
            "separation_of_duties",
            lambda g: g.__setitem__("separation_of_duties", {"not": [{"approver_of": "Gate"}]}),
        ),
        (
            "separation_of_duties",
            lambda g: g.__setitem__("separation_of_duties", {"not": [{"approver_of": "g!"}]}),
        ),
    ],
)
def test_gate_fields_are_closed_vocabularies_and_anchored_patterns(
    location: str, edit: Any
) -> None:
    err = _mutate(lambda s: edit(s["review_gate"]["gate"]))
    assert any(i.path.startswith(f"stages.review_gate.gate.{location}") for i in err.issues), str(
        err
    )


@pytest.mark.parametrize(
    ("stage", "edit"),
    [
        (
            "review_gate",
            lambda st: st["next"].__setitem__(
                "changes_requested", {"to": "Bad Id", "loop": "human_review"}
            ),
        ),
        (
            "review_gate",
            lambda st: st["next"].__setitem__(
                "changes_requested", {"to": "implement", "loop": "Human"}
            ),
        ),
        (
            "review_gate",
            lambda st: st["next"].__setitem__(
                "changes_requested", {"to": "implement!", "loop": "x"}
            ),
        ),
        (
            "review_gate",
            lambda st: st["next"].__setitem__(
                "changes_requested", {"to": "implement", "loop": "x!"}
            ),
        ),
        ("triage", lambda st: st.__setitem__("agent", "triage agent")),
        ("triage", lambda st: st.__setitem__("agent", "triage!")),
        ("llm_review", lambda st: st.__setitem__("reviewers", ["correctness_reviewer!"])),
        ("llm_review", lambda st: st.__setitem__("required", ["x y"])),
        ("await_info", lambda st: st.__setitem__("wait_for", "forever")),
        ("await_info", lambda st: st.__setitem__("timeout", "10d!")),
        ("trust_route", lambda st: st.__setitem__("field", "mood")),
        ("trust_route", lambda st: st.__setitem__("order", [])),
        ("trust_route", lambda st: st.__setitem__("order", [" "])),
        ("ci", lambda st: st.__setitem__("source", "vibes")),
        ("ci", lambda st: st.__setitem__("required", [" "])),
        ("ci", lambda st: st.__setitem__("required", ["a", ""])),
        ("llm_review", lambda st: st.__setitem__("fail_closed", "yes please")),
        ("done", lambda st: st.__setitem__("result", "approved")),
    ],
)
def test_stage_fields_are_closed_vocabularies_and_anchored_patterns(stage: str, edit: Any) -> None:
    err = _mutate(lambda s: edit(s[stage]))
    assert any(i.path.startswith(f"stages.{stage}") for i in err.issues), str(err)


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["intake"].__setitem__("source", "gitlab"),
        lambda d: d["intake"].__setitem__("label", " "),
        lambda d: d["intake"].__setitem__("project", ""),
        lambda d: d["intake"].__setitem__("issue_types", []),
        lambda d: d["intake"].__setitem__("sprint", {"mode": "sometimes"}),
        lambda d: d["repo"].__setitem__("sandbox_image", "Java 21"),
        lambda d: d["repo"].__setitem__("sandbox_image", ""),
        lambda d: d.__setitem__("start", "Start"),
        lambda d: d.__setitem__("start", "triage!"),
        lambda d: d.__setitem__("on_external_commit", "ci stage"),
        lambda d: d["metadata"].__setitem__("name", "Bad Name"),
        lambda d: d["metadata"].__setitem__("team", "bad team"),
        lambda d: d.__setitem__("stages", {}),
        lambda d: d["definition_of_done"][0].__setitem__("check", "vibes"),
    ],
)
def test_workflow_top_level_fields_are_closed(edit: Any) -> None:
    data = _std_data()
    data["intake"] = {"source": "jira", "project": "PAY", "label": "agent-ready"}
    data["repo"] = {"name": "example/payments", "base": "main", "sandbox_image": "java21"}
    edit(data)
    with pytest.raises(SchemaError):
        load_document(yaml.safe_dump(data))


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("start: refine", "start: Bad"),
        ("start: refine", "start: bad id"),
        ("on_external_commit: ci", "on_external_commit: Ci"),
    ],
)
def test_overlay_top_level_fields_are_identifiers(old: str, new: str) -> None:
    base = OVERLAY.replace(
        "extends: standard@1", "extends: standard@1\nstart: refine\non_external_commit: ci"
    )
    _refused(base.replace(old, new))


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["budgets"].__setitem__("team_monthly_usd", 0),
        lambda d: d["budgets"].__setitem__("team_monthly_usd", -5),
        lambda d: d["budgets"].__setitem__("run_usd", 0),
        lambda d: d["budgets"]["stage_usd"].__setitem__("implement", 0),
        lambda d: d["budgets"]["stage_usd"].__setitem__("implement", -1),
        lambda d: d["budgets"]["stage_usd"].__setitem__("Implement", 1),
        lambda d: d["budgets"].__setitem__("session_seconds_per_run", 0),
        lambda d: d["custom_profiles"]["pci_reviewer"].__setitem__("tools", []),
        lambda d: d["custom_profiles"]["pci_reviewer"].__setitem__("prompt_addendum", " "),
        lambda d: d["custom_profiles"].__setitem__("Bad Name", {"base": "x"}),
        lambda d: d["calendar"].__setitem__("timezone", " "),
        lambda d: d["calendar"].__setitem__("workdays", []),
        lambda d: d["sprint"].__setitem__("merge_freeze_before_end", "1 day"),
        lambda d: d["metadata"].__setitem__("team", "bad team"),
    ],
)
def test_team_config_numbers_and_names_are_bounded(edit: Any) -> None:
    data = _doc("TeamConfig")
    edit(data)
    assert _must_fail(data).issues


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["teams"]["ledger"].__setitem__("allowed_carry_over", []),
        lambda d: d["teams"]["ledger"].__setitem__("min_quorum", {"review": 0}),
        lambda d: d["teams"]["ledger"].__setitem__("min_quorum", {"mystery": 1}),
        lambda d: d["teams"]["ledger"]["required_gates"][0].__setitem__("role", "Security Officer"),
        lambda d: d["teams"]["ledger"]["required_gates"][0].__setitem__("id", "Gate"),
        lambda d: d["teams"]["ledger"]["required_gates"][1]["when"].__setitem__("field", "mood"),
        lambda d: d["teams"]["ledger"]["required_gates"][1]["when"].__setitem__("value", " "),
        lambda d: d["teams"].__setitem__("bad team", {}),
        lambda d: d["floors"].__setitem__("hold_after_approval_min", "10m!"),
        lambda d: d["floors"].__setitem__("identity_max_age", "8 h"),
        lambda d: d["floors"].__setitem__("require_up_to_date_waived_for", [" "]),
        lambda d: d["floors"]["decision_surfaces"].__setitem__("review", ["email"]),
        lambda d: d["floors"]["decision_surfaces"].__setitem__("bogus", ["ui"]),
        lambda d: d["floors"].__setitem__("decision_surfaces", {}),
        lambda d: d["floors"].__setitem__("requester_excluded_from", ["merge"]),
    ],
)
def test_org_policy_fields_are_bounded(edit: Any) -> None:
    data = _doc("OrgPolicy")
    edit(data)
    assert _must_fail(data).issues


_EFFECTS = [
    "branch.push",
    "branch.promote",
    "pr.ensure_draft",
    "pr.update_branch",
    "pr.mark_ready",
    "pr.merge",
    "pr.open_revert",
    "ticket.comment",
    "ticket.transition",
    "env.deploy_preview",
    "release.trigger",
    "notify",
]
_EXTRA_OUTCOMES = {
    "pr.merge": {"conflict", "stale"},
    "pr.update_branch": {"conflict"},
    "release.trigger": {"stale"},
}


@pytest.mark.parametrize("effect", _EFFECTS)
def test_each_effect_has_exactly_its_own_outcomes(effect: str) -> None:
    assert set(schema.Effect.__args__) == set(_EFFECTS)  # type: ignore[attr-defined]
    allowed = {"done"} | _EXTRA_OUTCOMES.get(effect, set())
    for outcome in ("done", "conflict", "stale"):
        text = _effect_doc(effect, f"{outcome}: e")
        if outcome in allowed:
            assert isinstance(load_document(text), Workflow), (effect, outcome)
        else:
            err = _refused(text)
            assert any(outcome in i.message and i.path == "stages.x.next" for i in err.issues)


def test_a_gate_has_no_timeout_outcome_but_a_wait_has() -> None:
    err = _mutate(lambda s: s["review_gate"]["next"].__setitem__("timeout", "promote"))
    assert any(
        "timeout" in i.message and i.path.startswith("stages.review_gate.next") for i in err.issues
    )
    err = _mutate(lambda s: s["qa_gate"]["next"].__setitem__("timeout", "mark_ready"))
    assert err.issues
    assert "timeout" not in schema.GATE_OUTCOMES
    assert "timeout" in (schema.OUTCOMES_BY_KIND["wait"] or set())
    # expired and retest remain legal gate outcomes (the regulated overlay uses expired)
    assert {"expired", "retest"} <= schema.GATE_OUTCOMES


def test_a_gate_without_any_approval_decision_still_has_only_human_outcomes() -> None:
    assert {
        "approved",
        "changes_requested",
        "rejected",
        "retest",
        "expired",
    } == schema.GATE_OUTCOMES


def test_overlay_patches_are_strict_and_frozen() -> None:
    for old, new in [
        ("  merge: null", '  merge: { max_attempts: "3" }'),
        ("  merge: null", "  merge: { max_attempts: 3.0 }"),
        ("  merge: null", "  merge: { fail_closed: 1 }"),
        (
            "    gate: { timeouts: { remind_after: 4h } }",
            "    gate: { timeouts: { remind_after: 4 } }",
        ),
        ("    gate: { timeouts: { remind_after: 4h } }", "    gate: { carry_over: true }"),
    ]:
        _refused(OVERLAY.replace(old, new))
    ov = load_document(OVERLAY)
    assert isinstance(ov, WorkflowOverlay)
    assert ov.stages is not None
    patch = ov.stages["review_gate"]
    assert patch is not None
    assert patch.gate is not None
    with pytest.raises(Exception, match="frozen"):
        patch.gate.carry_over = "none"
    assert schema.StagePatch.model_config["strict"] is True
    assert schema.StagePatch.model_config["frozen"] is True
    assert schema.WorkflowOverlay.model_config["strict"] is True
    assert schema.WorkflowOverlay.model_config["frozen"] is True


def test_every_stage_patch_field_matches_a_stage_field() -> None:
    stage_fields = set()
    for model in (
        schema.AgentStage,
        schema.ReviewPanelStage,
        schema.ChecksStage,
        schema.GateStage,
        schema.EffectStage,
        schema.WaitStage,
        schema.RouteStage,
        schema.TerminalStage,
    ):
        stage_fields |= {f.alias or n for n, f in model.model_fields.items()}
    patch_fields = {f.alias or n for n, f in schema.StagePatch.model_fields.items()}
    assert patch_fields == stage_fields


def test_an_unknown_key_with_a_block_value_is_reported_on_the_key_line() -> None:
    text = STANDARD.replace(
        "      type: review\n", "      type: review\n      bonus:\n        nested: 1\n", 1
    )
    (issue,) = _refused(text).issues
    assert issue.line == _line_of(text, "bonus:")
    assert issue.path == "stages.review_gate.gate.bonus"


def test_the_error_for_a_bad_block_value_points_at_its_key() -> None:
    text = STANDARD.replace(
        "      eligible_roles: [reviewer]\n", "      eligible_roles:\n        - Reviewer\n", 1
    )
    err = _refused(text)
    assert any(i.line == _line_of(text, "- Reviewer") for i in err.issues)
    text = STANDARD.replace("      eligible_roles: [reviewer]\n", "      eligible_roles:\n", 1)
    err = _refused(text)
    assert any(i.path.endswith("eligible_roles") for i in err.issues)


def test_duplicate_key_message_names_the_first_line() -> None:
    text = STANDARD.replace("start: triage\n", "start: triage\nstart: refine\n", 1)
    (issue,) = _refused(text).issues
    assert f"line {_line_of(text, 'start: triage')}" in issue.message


@pytest.mark.parametrize("word", ["on", "On", "ON"])
def test_every_spelling_of_on_gets_the_next_explanation(word: str) -> None:
    text = STANDARD.replace("start: triage", f"{word}: x\nstart: triage")
    assert "`next`" in _refused(text).issues[0].message


@pytest.mark.parametrize("word", ["off", "yes", "No"])
def test_other_booleans_are_refused_without_claiming_to_be_on(word: str) -> None:
    text = STANDARD.replace("start: triage", f"{word}: x\nstart: triage")
    assert "`next`" not in _refused(text).issues[0].message


def test_the_unsafe_loader_is_not_in_use_and_python_tags_run_nothing(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    path = "!!python/object/apply:pathlib.Path"
    payload = f"zzz: !!python/object/apply:pathlib.Path.write_text [{path} [{marker}], x]\n"
    _refused(MIN + payload)
    assert not marker.exists()
    assert issubclass(schema._Loader, yaml.SafeLoader)
    assert not issubclass(schema._Loader, yaml.UnsafeLoader)


def test_the_json_schema_says_it_is_only_a_hint() -> None:
    for doc in schema.json_schemas().values():
        assert doc["description"] == schema.EDITOR_NOTE
        assert "authority" in doc["description"]
        assert "looser" in doc["description"]


def test_json_schema_length_limits_use_array_and_object_words() -> None:
    overlay = schema.json_schemas()["workflow-overlay"]["$defs"]["GatePatch"]["properties"]
    assert overlay["eligible_roles"]["anyOf"][0]["minItems"] == 1
    for doc in schema.json_schemas().values():
        for obj in _all_nodes(doc):
            if obj.get("type") in ("array", "object"):
                assert "minLength" not in obj, obj
    gate = schema.json_schemas()["workflow"]["$defs"]["Gate"]
    assert gate["properties"]["eligible_roles"]["minItems"] == 1
    stages = schema.json_schemas()["workflow"]["properties"]["stages"]
    assert stages["minProperties"] == 1


def _all_nodes(node: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        out.append(node)
        for v in node.values():
            out.extend(_all_nodes(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_all_nodes(v))
    return out


def test_unexpected_value_errors_from_inside_are_still_schema_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(text: str, source: str) -> None:
        raise ValueError("internal")

    monkeypatch.setattr(schema, "_load", boom)
    err = _refused(MIN)
    assert "ValueError" in str(err)


def test_non_finite_numbers_are_refused_inside_with() -> None:
    _refused(_with_value("1e999"))
    _refused(_with_value("[1, 1e999]"))
    with pytest.raises(Exception, match="NaN"):
        schema._json_only(float("nan"))


@pytest.mark.parametrize(
    "number", ["1_0.5", "1:00.5", "+5.0", "0x1.8", "1,5", ".5", "5.", "1e", "--1"]
)
def test_odd_float_spellings_are_not_numbers(number: str) -> None:
    _refused(TEAM.replace("run_usd: 40", f"run_usd: {number}"))


# =============================================================================================
# Review pass 2
# =============================================================================================

# --- 1. no stray exceptions from construction or the timezone lookup --------------------------


@pytest.mark.parametrize(
    "raw",
    ["!!bool maybe", "!!bool yes", "!!timestamp foo", "!!int abc", "!!float x", "!!null x"],
)
def test_bad_values_under_an_explicit_core_tag_are_line_numbered_schema_errors(raw: str) -> None:
    text = MIN + f"zzz: {raw}\n"
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, "zzz:")


@pytest.mark.parametrize("raw", ["!!bool maybe", "!!timestamp foo"])
def test_the_same_bad_tags_as_keys_are_schema_errors(raw: str) -> None:
    _refused(MIN + f"? {raw}\n: 1\n")


@pytest.mark.parametrize("base", ["null", "~"])
def test_overlay_repo_base_null_is_a_removal_and_loads(base: str) -> None:
    text = OVERLAY.replace("  merge: null", "  merge: null\nrepo: { base: " + base + " }")
    ov = load_document(text)
    assert isinstance(ov, WorkflowOverlay)
    assert ov.repo is not None
    assert ov.repo.base is None
    assert "base" in ov.repo.model_fields_set


def test_timezone_that_is_a_directory_is_a_schema_error() -> None:
    err = _refused(TEAM.replace("Europe/London", "Europe"))
    assert any(i.path == "calendar.timezone" for i in err.issues)
    with pytest.raises(ValueError, match="unknown timezone"):
        schema._timezone("Europe")


@pytest.mark.parametrize("zone", ["../x", "a/../b", "/etc/passwd", "\x00", "x" * 5000])
def test_timezone_lookup_failures_are_value_errors_with_our_message(zone: str) -> None:
    with pytest.raises(ValueError, match="unknown timezone"):
        schema._timezone(zone)


@pytest.mark.parametrize("zone", ["localtime", "posixrules", "Factory"])
def test_names_in_the_tz_database_that_are_not_places_are_refused(zone: str) -> None:
    with pytest.raises(ValueError, match="unknown timezone"):
        schema._timezone(zone)
    _refused(TEAM.replace("Europe/London", zone))


def test_timezones_resolve_without_the_system_database(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no system tz path the tzdata package must answer, so dropping it fails on any host."""
    import zoneinfo

    monkeypatch.setattr(zoneinfo, "TZPATH", ())
    zoneinfo.ZoneInfo.clear_cache()
    try:
        zoneinfo.reset_tzpath(to=[])
        assert zoneinfo.TZPATH == ()
        assert schema._timezone("Europe/London") == "Europe/London"
        assert isinstance(load_document(TEAM), TeamConfig)
        with pytest.raises(ValueError, match="unknown timezone"):
            schema._timezone("Mars/Phobos")
    finally:
        zoneinfo.reset_tzpath()
        zoneinfo.ZoneInfo.clear_cache()


def test_tzdata_is_a_declared_runtime_dependency() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    head = text.split("[dependency-groups]")[0]
    assert '"tzdata' in head


# --- 2. nulls on constrained overlay fields load as removals ---------------------------------

_NULL_FIELDS = [
    "repo: {base: null}",
    "repo: {name: null}",
    "repo: {sandbox_image: null}",
    "intake: {project: null}",
    "intake: {issue_types: null}",
    "intake: {sprint: null}",
    "intake: {sprint: {mode: null}}",
    "limits: {max_run_age: null}",
    "limits: {max_steps_per_run: null}",
    "limits: {loops: null}",
    "definition_of_done: null",
    "stages: {g: {gate: {eligible_roles: null}}}",
    "stages: {g: {gate: {decisions: null}}}",
    "stages: {g: {gate: {decision_surfaces: null}}}",
    "stages: {g: {gate: {quorum: null}}}",
    "stages: {g: {gate: {separation_of_duties: null}}}",
    "stages: {g: {gate: {separation_of_duties: {not: null}}}}",
    "stages: {g: {gate: {carry_over: null}}}",
    "stages: {g: {gate: {timeouts: null}}}",
    "stages: {g: {gate: {timeouts: {expire_after: null}}}}",
    "stages: {g: {requires_gates: null}}",
    "stages: {g: {timeout: null}}",
    "stages: {g: {reviewers: null}}",
    "stages: {g: {required: null}}",
    "stages: {g: {next: null}}",
    "stages: {g: {next: {a: null}}}",
    "stages: {g: {with: null}}",
    "stages: {g: {max_attempts: null}}",
    "stages: {g: null}",
]


@pytest.mark.parametrize("body", _NULL_FIELDS)
def test_a_null_in_an_overlay_patch_field_loads_and_is_kept_as_a_removal(body: str) -> None:
    ov = load_document(OVERLAY.split("stages:")[0] + body + "\n")
    assert isinstance(ov, WorkflowOverlay)
    patch = ov.to_patch()
    assert patch  # the removal survived into the patch body
    # a re-load of the patch body gives the same overlay: nothing was lost
    head = {k: getattr(ov, k) for k in ("apiVersion", "kind")}
    again = load_document(
        yaml.safe_dump(
            {**head, "metadata": {"name": "o", "team": "t"}, "extends": "standard@1", **patch}
        )
    )
    assert again == ov


@pytest.mark.parametrize(
    "body",
    [
        "stages: {g: {next: {a: {to: null}}}}",
        "definition_of_done: [{stage: a, check: ac_present, value: null}]",
        "stages: {g: {gate: {quorum: [{role: null, count: 1}]}}}",
        "stages: {g: {gate: {separation_of_duties: {not: [null]}}}}",
        "stages: {g: {gate: {eligible_roles: [null]}}}",
    ],
)
def test_nulls_below_a_replaced_list_or_inside_an_edge_are_still_refused(body: str) -> None:
    err = _refused(OVERLAY.split("stages:")[0] + body + "\n")
    assert all(i.line is not None for i in err.issues)
    assert "full document" not in str(err)


def test_the_removal_message_does_not_call_an_overlay_a_full_document() -> None:
    err = _refused(OVERLAY.split("stages:")[0] + "stages: {g: {next: {a: {to: null}}}}\n")
    assert "full document" not in str(err)
    assert "WorkflowOverlay" in str(err)
    with pytest.raises(Exception, match="WorkflowOverlay"):
        schema.Edge.model_validate({"to": None})


@pytest.mark.parametrize("field", ["max_run_age", "max_steps_per_run"])
def test_a_removed_limit_is_refused_when_the_flattened_workflow_is_validated(field: str) -> None:
    """D2-02 re-validates the flattened document; a removed mandatory field must fail there."""
    data = _std_data()
    del data["limits"][field]
    with pytest.raises(SchemaError):
        load_document(yaml.safe_dump(data))


def test_removing_a_gates_roles_leaves_a_workflow_that_will_not_load() -> None:
    data = _std_data()
    del data["stages"]["review_gate"]["gate"]["eligible_roles"]
    with pytest.raises(SchemaError):
        load_document(yaml.safe_dump(data))
    del data["stages"]["review_gate"]["gate"]
    with pytest.raises(SchemaError):
        load_document(yaml.safe_dump(data))


def test_overlay_validators_check_the_value_and_never_run_on_none() -> None:
    for body in (
        "repo: {base: '--upload-pack=x'}",
        "repo: {name: '../..'}",
        "limits: {max_run_age: 301d}",
        "limits: {max_run_age: 2 days}",
        "stages: {g: {gate: {eligible_roles: []}}}",
        "stages: {g: {gate: {decisions: []}}}",
        "stages: {g: {gate: {decision_surfaces: []}}}",
        "stages: {g: {gate: {separation_of_duties: {not: []}}}}",
    ):
        err = _refused(OVERLAY.split("stages:")[0] + body + "\n")
        assert all(i.line is not None for i in err.issues), body
        assert "could not be read" not in str(err), body


# --- 3. lone surrogates ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    ['"\\ud800"', '"x\\udfffy"', '"\\ud83d"'],
)
def test_a_lone_surrogate_in_with_is_refused_at_load(raw: str) -> None:
    text = _with_value(raw)
    err = _refused(text)
    assert any("surrogate" in i.message for i in err.issues)
    assert err.issues[0].line is not None


def test_a_lone_surrogate_in_a_with_key_or_any_string_is_refused() -> None:
    err = _refused(_with_value('{"\\ud800": 1}'))
    assert any("surrogate" in i.message for i in err.issues)
    err = _refused(MIN + 'zzz: "\\ud800"\n')
    assert any("surrogate" in i.message for i in err.issues)


def test_surrogates_are_refused_when_building_in_python_too() -> None:
    data = _std_data()
    data["stages"]["merge"]["with"] = {"a": "\ud800"}
    with pytest.raises(Exception, match="surrogate"):
        Workflow.model_validate(data)
    data["stages"]["merge"]["with"] = {"\ud800": 1}
    with pytest.raises(Exception, match="surrogate"):
        Workflow.model_validate(data)
    data["stages"]["merge"]["with"] = {"a": {"\ud800": 1}}
    with pytest.raises(Exception, match="surrogate"):
        Workflow.model_validate(data)
    data["stages"]["merge"]["with"] = {"a": [{"b": ["\udc00"]}]}
    with pytest.raises(Exception, match="surrogate"):
        Workflow.model_validate(data)


def test_non_string_keys_inside_with_are_refused_even_when_nested() -> None:
    data = _std_data()
    data["stages"]["merge"]["with"] = {"a": {1: "x"}}
    with pytest.raises(Exception, match="keys must be strings"):
        Workflow.model_validate(data)
    with pytest.raises(ValueError, match="keys must be strings"):
        schema._json_only({1: "x"})


def test_text_fields_refuse_surrogates_and_control_characters() -> None:
    for bad in ("a\nb", "a\tb", "a\x00b", "a\x1bb", "\ud800"):
        data = _doc("TeamConfig")
        data["qa"]["test_domains"] = [bad]
        assert _must_fail(data).issues, repr(bad)
    data = _doc("TeamConfig")
    data["custom_profiles"]["pci_reviewer"]["prompt_addendum"] = "line one\n\tline two"
    assert isinstance(load_document(yaml.safe_dump(data)), TeamConfig)
    data["custom_profiles"]["pci_reviewer"]["prompt_addendum"] = "bell\x07"
    assert _must_fail(data).issues
    data["custom_profiles"]["pci_reviewer"]["prompt_addendum"] = "\ud800"
    assert _must_fail(data).issues


# --- immutable mapping: pickle, deepcopy, model_copy ------------------------------------------


@pytest.mark.parametrize("block", PLAN_BLOCKS, ids=_block_id)
def test_documents_survive_pickle_deepcopy_and_deep_model_copy(block: str) -> None:
    doc = load_document(block)
    for clone in (
        pickle.loads(pickle.dumps(doc)),
        copy.deepcopy(doc),
        copy.copy(doc),
        doc.model_copy(deep=True),
    ):
        assert clone == doc
        assert type(clone) is type(doc)
        _assert_no_mutable_containers(clone)
    assert pickle.loads(pickle.dumps(doc, protocol=pickle.HIGHEST_PROTOCOL)) == doc


def test_a_copied_document_is_still_immutable() -> None:
    wf = load_document(STANDARD)
    assert isinstance(wf, Workflow)
    clone = copy.deepcopy(wf)
    with pytest.raises(TypeError):
        clone.limits.loops["x"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        clone.stages["merge"] = clone.stages["done"]  # type: ignore[index]
    assert isinstance(clone.stages, schema.FrozenMap)
    assert clone.stages is not wf.stages


def test_frozen_map_behaves_like_a_read_only_dict() -> None:
    m = schema.FrozenMap({"a": 1, "b": [1]})
    plain = {"a": 1, "b": [1]}
    assert m == plain
    assert plain == m
    assert dict(m) == {"a": 1, "b": [1]}
    assert list(m) == ["a", "b"]
    assert len(m) == 2
    assert "a" in m
    assert m.get("zz") is None
    assert repr(m) == "FrozenMap({'a': 1, 'b': [1]})"
    assert pickle.loads(pickle.dumps(m)) == m
    assert copy.deepcopy(m) == m
    assert copy.deepcopy(m) is not m
    with pytest.raises(TypeError):
        m["a"] = 2  # type: ignore[index]
    with pytest.raises(TypeError):
        del m["a"]  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        m.update({"c": 1})  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        m._data = {}
    with pytest.raises(AttributeError):
        del m._data
    with pytest.raises(TypeError):
        hash(m)
    assert schema.FrozenMap() == {}
    assert "not hashable" in (schema.FrozenMap.__doc__ or "")


def test_schema_error_pickles() -> None:
    err = _refused(MIN + "zzz: 1\nzzz: 2\n")
    again = pickle.loads(pickle.dumps(err))
    assert isinstance(again, SchemaError)
    assert again.issues == err.issues
    assert again.source == err.source
    assert str(again) == str(err)
    copy.deepcopy(err)


def test_overlay_patch_classes_pickle_too() -> None:
    ov = load_document(OVERLAY)
    assert pickle.loads(pickle.dumps(ov)) == ov
    for block in OVERLAYS:
        doc = load_document(block)
        assert pickle.loads(pickle.dumps(doc)) == doc


# --- to_patch is the body only ---------------------------------------------------------------


def test_to_patch_leaves_out_the_overlay_head() -> None:
    ov = load_document(OVERLAY)
    assert isinstance(ov, WorkflowOverlay)
    assert ov.to_patch() == {
        "stages": {"review_gate": {"gate": {"timeouts": {"remind_after": "4h"}}}, "merge": None}
    }
    doc = WorkflowOverlay.to_patch.__doc__ or ""
    assert "kind" in doc
    assert "metadata" in doc
    assert not hasattr(schema.StagePatch, "to_patch")  # a stage's own `kind` must not be stripped


def test_a_stage_patch_dump_keeps_its_own_kind() -> None:
    text = OVERLAY.replace("  merge: null", "  merge: {kind: effect, effect: pr.merge}")
    ov = load_document(text)
    assert isinstance(ov, WorkflowOverlay)
    assert ov.to_patch()["stages"]["merge"] == {"kind": "effect", "effect": "pr.merge"}


# --- caps, escaping and wording --------------------------------------------------------------


def test_thousands_of_problems_give_a_bounded_message() -> None:
    text = "\n".join(f"k: {i}" for i in range(32000))
    err = _refused(text)
    assert len(err.issues) == schema.MAX_ISSUES + 1
    assert err.issues[-1].message.startswith("31")  # 31,999 repeats less the 50 shown
    assert "more problems not shown" in err.issues[-1].message
    assert len(str(err)) < 20000


def test_many_model_errors_are_capped_too() -> None:
    stages = "".join(f"  s{i}: {{kind: sleep}}\n" for i in range(200))
    err = _refused(MIN + stages.replace("s", "x", 0))
    assert len(err.issues) <= schema.MAX_ISSUES + 1


def test_schema_error_caps_issues_given_directly() -> None:
    many = [schema.Issue(1, "p", f"m{i}") for i in range(schema.MAX_ISSUES + 7)]
    assert len(SchemaError(many).issues) == schema.MAX_ISSUES + 1
    assert "7 more" in SchemaError(many).issues[-1].message
    assert len(SchemaError(many[: schema.MAX_ISSUES]).issues) == schema.MAX_ISSUES


@pytest.mark.parametrize("word", ["yes", "no", "on", "off"])
def test_yaml_1_1_boolean_words_as_values_are_not_booleans(word: str) -> None:
    text = STANDARD.replace("block_on: high", f"block_on: high\n    fail_closed: {word}")
    err = _refused(text)
    assert any(i.path == "stages.llm_review.fail_closed" for i in err.issues)
    assert any("bool" in i.message for i in err.issues)


@pytest.mark.parametrize("word", ["true", "false"])
def test_true_and_false_are_the_only_booleans(word: str) -> None:
    text = STANDARD.replace("block_on: high", f"block_on: high\n    fail_closed: {word}")
    wf = load_document(text)
    assert isinstance(wf, Workflow)
    assert wf.stages["llm_review"].fail_closed is (word == "true")  # type: ignore[union-attr]


@pytest.mark.parametrize("word", ["True", "TRUE", "False", "Yes", "ON"])
def test_capitalised_booleans_are_refused_too(word: str) -> None:
    text = STANDARD.replace("block_on: high", f"block_on: high\n    fail_closed: {word}")
    _refused(text)


def test_a_word_that_yaml_11_calls_a_boolean_is_plain_text_in_a_text_field() -> None:
    text = STANDARD.replace("eligible_roles: [reviewer]", "eligible_roles: [yes]", 1)
    wf = load_document(text)
    assert isinstance(wf, Workflow)
    assert wf.stages["pre_push_gate"].gate.eligible_roles == ("yes",)  # type: ignore[union-attr]


def test_a_quoted_boolean_word_is_still_a_usable_key() -> None:
    text = STANDARD.replace(
        "next: { attested: push, default: pre_push_gate }",
        'next: { attested: push, "yes": push, "no": push, default: pre_push_gate }',
    )
    assert isinstance(load_document(text), Workflow)


def test_the_loader_docstring_promises_only_what_it_delivers() -> None:
    doc = load_document.__doc__ or ""
    assert "SchemaError" in doc
    assert "No other exception" in doc


# --- bounds the review found open -------------------------------------------------------------


@pytest.mark.parametrize("value", ["101", "100.5", "-5", "-0.1", "1000", "true"])
def test_coverage_is_a_percentage(value: str) -> None:
    text = STANDARD.replace(
        "  - { stage: review_gate, check: checks_green }",
        f"  - {{ stage: review_gate, check: coverage_at_least, value: {value} }}",
    )
    err = _refused(text)
    assert err.issues
    if value != "true":
        assert any("coverage_at_least" in i.message for i in err.issues)


@pytest.mark.parametrize("value", ["0", "80", "100", "99.5", "0.0"])
def test_coverage_accepts_the_whole_percentage_range(value: str) -> None:
    text = STANDARD.replace(
        "  - { stage: review_gate, check: checks_green }",
        f"  - {{ stage: review_gate, check: coverage_at_least, value: {value} }}",
    )
    assert isinstance(load_document(text), Workflow)


@pytest.mark.parametrize("value", ["bogus", "Low", "5", "''", "null", "true", "[low]"])
def test_no_findings_above_takes_a_severity(value: str) -> None:
    check = "no_findings_above"
    text = STANDARD.replace(
        "  - { stage: review_gate, check: checks_green }",
        f"  - {{ stage: review_gate, check: {check}, value: {value} }}",
    )
    err = _refused(text)
    assert err.issues


@pytest.mark.parametrize("value", ["low", "medium", "high", "critical"])
def test_no_findings_above_accepts_each_severity(value: str) -> None:
    text = STANDARD.replace(
        "  - { stage: review_gate, check: checks_green }",
        f"  - {{ stage: review_gate, check: no_findings_above, value: {value} }}",
    )
    assert isinstance(load_document(text), Workflow)


@pytest.mark.parametrize("check", ["ac_present", "checks_green"])
def test_checks_without_a_parameter_refuse_one(check: str) -> None:
    text = STANDARD.replace(
        "  - { stage: review_gate, check: checks_green }",
        f"  - {{ stage: review_gate, check: {check}, value: 3 }}",
    )
    _refused(text)


def test_note_that_exclude_none_would_drop_removals() -> None:
    """D2-02 must not use exclude_none on an overlay: it drops every explicit null (a removal)."""
    ov = load_document(OVERLAY)
    assert isinstance(ov, WorkflowOverlay)
    kanban = load_document(next(b for b in OVERLAYS if "platform-kanban" in b))
    assert isinstance(kanban, WorkflowOverlay)
    assert "definition_of_done" in kanban.model_dump()
    assert "definition_of_done" not in kanban.model_dump(exclude_none=True)  # the trap
    assert kanban.to_patch()["definition_of_done"] is None
    assert "None" in (WorkflowOverlay.to_patch.__doc__ or "")


def test_effect_outcomes_are_the_single_table_a_catalog_check_can_read() -> None:
    """D2-18's catalog must agree with EFFECT_OUTCOMES; this pins the shape that check compares."""
    assert set(schema.EFFECT_OUTCOMES) == {"pr.merge", "pr.update_branch", "release.trigger"}
    assert all("done" in v for v in schema.EFFECT_OUTCOMES.values())


# =============================================================================================
# Review pass 3
# =============================================================================================


@pytest.mark.parametrize("word", sorted(schema._YAML11_BOOL_WORDS))
def test_every_yaml_1_1_boolean_spelling_is_refused_as_a_plain_key(word: str) -> None:
    text = MIN + f"{word}: 1\n"
    err = _refused(text)
    assert err.issues[0].line == _line_of(text, f"{word}: 1")
    assert "boolean" in err.issues[0].message


@pytest.mark.parametrize("word", sorted(schema._YAML11_BOOL_WORDS))
def test_every_yaml_1_1_boolean_spelling_is_fine_as_a_quoted_key(word: str) -> None:
    text = STANDARD.replace(
        "next: { attested: push, default: pre_push_gate }",
        f'next: {{ attested: push, "{word}": push, default: pre_push_gate }}',
    )
    assert isinstance(load_document(text), Workflow)


def test_the_boolean_word_set_is_what_pyyaml_reads_as_booleans() -> None:
    stems = ("yes", "no", "true", "false", "on", "off")
    expected = {w for stem in stems for w in (stem, stem.capitalize(), stem.upper())}
    assert expected == schema._YAML11_BOOL_WORDS
    for word in expected:
        assert yaml.safe_load(word) is (word.lower() in ("yes", "true", "on"))


def test_carriage_return_is_a_control_character_in_a_prompt_addendum() -> None:
    data = _doc("TeamConfig")
    for bad in ("one\rtwo", "one\r\ntwo", "\r"):
        data["custom_profiles"]["pci_reviewer"]["prompt_addendum"] = bad
        assert _must_fail(data).issues, repr(bad)
    data["custom_profiles"]["pci_reviewer"]["prompt_addendum"] = "one\ntwo\tthree"
    assert isinstance(load_document(yaml.safe_dump(data)), TeamConfig)


def test_mandatory_gate_roles_cannot_name_a_custom_gate() -> None:
    err = _refused(ORG.replace(_MGR, _MGR[:-2] + ", custom: [reviewer] }"))
    assert any("mandatory_gate_roles" in i.path for i in err.issues)
    assert set(schema.MANDATORY_GATES) == {"pre_push", "review", "qa"}


def test_dumps_hold_plain_dicts_and_lists_not_frozen_maps() -> None:
    wf = load_document(STANDARD)
    assert isinstance(wf, Workflow)
    dumped = wf.model_dump(by_alias=True)
    assert type(dumped["stages"]) is dict
    assert type(dumped["limits"]["loops"]) is dict
    assert type(dumped["stages"]["merge"]["next"]) is dict
    assert type(dumped["stages"]["merge"]["with"]) is dict
    assert type(dumped["stages"]["review_gate"]["gate"]["eligible_roles"]) is tuple
    nested = load_document(_with_value("{b: [1, {c: [2]}]}"))
    assert isinstance(nested, Workflow)
    plain = nested.model_dump(by_alias=True)["stages"]["e"]["with"]
    assert type(plain) is dict
    assert type(plain["a"]) is dict
    assert type(plain["a"]["b"]) is list
    assert type(plain["a"]["b"][1]) is dict
    assert type(plain["a"]["b"][1]["c"]) is list
    jsonable = nested.model_dump(mode="json", by_alias=True)["stages"]["e"]["with"]
    assert jsonable == {"a": {"b": [1, {"c": [2]}]}}
    org = load_document(ORG)
    assert isinstance(org, OrgPolicy)
    assert type(org.model_dump()["floors"]["mandatory_gate_roles"]) is dict
    assert type(org.model_dump()["teams"]) is dict


def test_the_frozen_map_docstring_names_the_way_out() -> None:
    doc = schema.FrozenMap.__doc__ or ""
    assert "model_dump" in doc
    for name in ("json.dumps", "to_jsonable_python", "yaml.safe_dump"):
        assert name in doc
    fm = schema.FrozenMap({"a": 1})
    with pytest.raises(TypeError):
        json.dumps(fm)
    with pytest.raises(yaml.YAMLError):
        yaml.safe_dump(fm)


# --- N1: a map in a patch merges key by key and null removes a key ----------------------------


def test_a_null_loop_limit_in_an_overlay_removes_that_loop() -> None:
    ov = load_document(OVERLAY.split("stages:")[0] + "limits: {loops: {a: null, b: 2}}\n")
    assert isinstance(ov, WorkflowOverlay)
    assert ov.limits is not None
    assert ov.limits.loops is not None
    assert dict(ov.limits.loops) == {"a": None, "b": 2}
    assert ov.to_patch() == {"limits": {"loops": {"a": None, "b": 2}}}


@pytest.mark.parametrize("value", ["0", "-1", "'x'", "1.5", "true"])
def test_a_loop_limit_that_is_not_null_must_still_be_a_positive_int(value: str) -> None:
    _refused(OVERLAY.split("stages:")[0] + f"limits: {{loops: {{a: {value}}}}}\n")


def test_a_full_workflow_still_refuses_a_null_loop() -> None:
    _refused(
        MIN.replace(
            "limits: {max_steps_per_run: 5,", "limits: {loops: {a: null}, max_steps_per_run: 5,"
        )
    )


# --- N2: instants must survive a dump and a reload unchanged ------------------------------------


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-01-01T00:00:00+01:00:30",
        "2026-01-01T00:00:00+00:00:01",
        "2026-01-01 00:00:00 +01:00:30",
        "'2026-01-01T00:00:00+01:00:30'",
        "2026-01-01T00:00:00-05:00:59",
    ],
)
def test_an_offset_with_seconds_is_refused(stamp: str) -> None:
    window = f"{{from: {stamp}, to: 2027-01-01T00:00:00Z, reason: x}}"
    err = _refused(_team_with(window))
    assert any("whole number of minutes" in i.message for i in err.issues), str(err)


@pytest.mark.parametrize(
    "stamp", ["2026-01-01T00:00:00+05:30", "2026-01-01T00:00:00-03:30", "2026-01-01T00:00:00Z"]
)
def test_whole_minute_offsets_round_trip_to_the_same_instant(stamp: str) -> None:
    window = f"{{from: {stamp}, to: 2027-01-01T00:00:00Z, reason: x}}"
    cfg = load_document(_team_with(window))
    assert isinstance(cfg, TeamConfig)
    again = TeamConfig.model_validate_json(
        cfg.model_dump_json(by_alias=True, exclude_none=True), strict=False
    )
    assert again == cfg
    assert again.change_windows is not None
    assert cfg.change_windows is not None
    assert again.change_windows.deny[0].from_ == cfg.change_windows.deny[0].from_


# --- N3: duplicate-key reporting is linear -----------------------------------------------------


class _CountingKey(yaml.ScalarNode):
    reads = 0

    @property
    def value(self) -> str:
        type(self).reads += 1
        return self._value

    @value.setter
    def value(self, v: str) -> None:
        self._value = v


def test_duplicate_key_reporting_does_not_rescan_the_mapping() -> None:
    """Counting reads of key nodes: a rescan per duplicate would make this quadratic."""
    n = 2000
    mark = yaml.Mark("x", 0, 0, 0, "", 0)

    def key(i: int, dup: bool) -> tuple[yaml.Node, yaml.Node]:
        k = _CountingKey("tag:yaml.org,2002:str", f"k{i}", mark, mark)
        v = yaml.ScalarNode("tag:yaml.org,2002:int", "1", mark, mark)
        return k, v

    pairs = [key(i, False) for i in range(n)] + [key(i, True) for i in range(n)]
    node = yaml.MappingNode("tag:yaml.org,2002:map", pairs, mark, mark)
    loader = schema._Loader("")
    _CountingKey.reads = 0
    loader.construct_mapping(node)
    assert len(loader.problems) == schema.MAX_ISSUES
    assert loader.dropped == n - schema.MAX_ISSUES
    assert _CountingKey.reads < 12 * n, _CountingKey.reads  # quadratic would be about n*n/2


def test_each_duplicate_names_the_line_of_its_first_occurrence() -> None:
    text = "a: 1\nb: 2\nc: 3\nb: 4\nc: 5\na: 6\n"
    err = _refused(text)
    assert [(i.line, i.message.split("line ")[-1]) for i in err.issues] == [
        (4, "2"),
        (5, "3"),
        (6, "1"),
    ]


# --- N4: huge integers never overflow ----------------------------------------------------------


def test_a_huge_coverage_integer_is_a_value_error_not_an_overflow() -> None:
    huge = int("9" * 400)
    for value in (huge, -huge):
        with pytest.raises(Exception, match="coverage_at_least"):
            schema.DefinitionOfDone.model_validate(
                {"stage": "a", "check": "coverage_at_least", "value": value}
            )


@pytest.mark.parametrize("digits", [400, 4000])
def test_a_huge_coverage_integer_in_a_document_is_a_line_numbered_refusal(digits: int) -> None:
    text = STANDARD.replace(
        "  - { stage: review_gate, check: checks_green }",
        f"  - {{ stage: review_gate, check: coverage_at_least, value: {'9' * digits} }}",
    )
    err = _refused(text)
    assert all(i.line is not None for i in err.issues)


# --- N5: plain messages for loader problems ----------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "!!timestamp foo",
        "!!bool maybe",
        "!!int abc",
        "!!float x",
        "!!null x",
        "!!int [1]",
        "!!str {a: 1}",
    ],
)
def test_loader_messages_do_not_leak_pyyaml_internals(raw: str) -> None:
    for text in (MIN + f"zzz: {raw}\n", MIN + f"? {raw}\n: 1\n"):
        err = _refused(text)
        blob = str(err)
        for leak in ("NoneType", "groupdict", "Node", "object has no attribute", "<root>", "0x"):
            assert leak not in blob, (leak, blob)
        assert all(i.line is not None for i in err.issues)


def test_a_loader_problem_reads_as_line_and_message_without_a_fake_path() -> None:
    text = MIN + "zzz: !!timestamp foo\n"
    (issue,) = _refused(text).issues
    assert str(issue) == f"line {_line_of(text, 'zzz')}: {issue.message}"
    assert "timestamp" in issue.message
    assert str(schema.Issue(3, "a.b", "m")) == "line 3: a.b: m"
    assert str(schema.Issue(None, "", "m")) == "document: m"


# --- N8: not-a-document arguments --------------------------------------------------------------


@pytest.mark.parametrize("value", [None, 5, [], {}, 1.5])
def test_load_document_refuses_a_non_text_argument_with_a_schema_error(value: Any) -> None:
    with pytest.raises(SchemaError) as info:
        load_document(value)
    assert "text or bytes" in str(info.value)
