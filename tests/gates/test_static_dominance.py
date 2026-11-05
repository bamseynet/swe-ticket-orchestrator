"""G2, static dominance (PLAN 15.3): V4 and V5 on every template, and mutation.

``test_integrity`` proves at run time that nothing gated runs before approval (G1). This proves
it before any run exists: on the stage graph of each template, a gated effect is unreachable
once any gate it lists has its approval edge removed. The mutation tests then break each
template in every way a team could (skip a gate, splice it out, list no gate, take away its
way out) and require the validator to say so. A validator that passed everything would fail
all of them.

"All templates" is the standard template and the three PLAN overlays on it, flattened. When the
bundled templates land (D2-05) this list is replaced by what ships.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from sto.config.manifest import load_manifest
from sto.config.overlays import flatten
from sto.config.schema import Workflow, WorkflowOverlay, load_document, load_workflow
from sto.config.validate_gates import check_gate_dominance

ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")
MANIFEST = load_manifest()


def _blocks() -> list[str]:
    section = PLAN[PLAN.index("## 7. Workflow configuration") : PLAN.index("## 8. Agents")]
    found = re.findall(r"```yaml\n(.*?)```", section, flags=re.S)
    return [b for b in found if "apiVersion: sto/v1" in b and ": string" not in b]


def _load(data: dict[str, Any]) -> Workflow:
    return load_workflow(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False))


def _templates() -> dict[str, dict[str, Any]]:
    blocks = _blocks()
    standard = _load(yaml.safe_load(next(b for b in blocks if "kind: Workflow\n" in b)))
    out = {"standard": _dump(standard)}
    for text in blocks:
        if "kind: WorkflowOverlay" not in text:
            continue
        ov = load_document(text)
        assert isinstance(ov, WorkflowOverlay)
        out[ov.metadata.name] = _dump(flatten(standard, ov, template_ref=ov.extends).workflow)
    return out


def _dump(wf: Workflow) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(wf.model_dump_json(exclude_unset=True, by_alias=True))
    return data


TEMPLATES = _templates()
NAMES = sorted(TEMPLATES)


def issues_of(data: dict[str, Any]) -> list[str]:
    return [f"{i.path}: {i.message}" for i in check_gate_dominance(_load(data), MANIFEST)]


def _gates(data: dict[str, Any]) -> list[str]:
    return [sid for sid, st in data["stages"].items() if st["kind"] == "gate"]


def _targets(stage: dict[str, Any]) -> Iterator[tuple[str, str]]:
    for outcome, edge in stage.get("next", {}).items():
        yield outcome, edge if isinstance(edge, str) else edge["to"]


def _retarget(stage: dict[str, Any], outcome: str, target: str) -> None:
    edge = stage["next"][outcome]
    if isinstance(edge, str):
        stage["next"][outcome] = target
    else:
        edge["to"] = target


def _incoming(data: dict[str, Any], gate: str) -> list[tuple[str, str]]:
    return [
        (sid, outcome)
        for sid, st in data["stages"].items()
        for outcome, target in _targets(st)
        if target == gate
    ]


def _dominating(data: dict[str, Any]) -> list[str]:
    """Gates that some gated effect lists: the ones dominance is about.

    The others (``pre_push_gate``, which V16 proves, and a gate an org requires, which V17 proves)
    guard something no effect lists, so the stage graph alone cannot say a path round them is wrong.
    """
    listed = {
        g
        for st in data["stages"].values()
        if st["kind"] == "effect"
        for g in st.get("requires_gates") or []
    }
    return [g for g in _gates(data) if g in listed]


# --- the templates pass -----------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_G2_every_template_proves_dominance_and_freshness(name: str) -> None:
    assert issues_of(TEMPLATES[name]) == []


def test_G2_the_suite_covers_the_standard_template_and_all_three_overlays() -> None:
    assert NAMES == ["ledger-regulated", "payments-scrum", "platform-kanban", "standard"]


@pytest.mark.parametrize("name", NAMES)
def test_G2_every_template_has_gated_effects_to_prove_something_about(name: str) -> None:
    data = TEMPLATES[name]
    gated = [
        sid
        for sid, st in data["stages"].items()
        if st["kind"] == "effect" and MANIFEST.effects[st["effect"]].effect_class == "gated"
    ]
    assert len(gated) >= 4, "a vacuous proof would pass every mutation below too"
    assert all(data["stages"][sid].get("requires_gates") for sid in gated)


# --- mutation: bypass a gate edge -------------------------------------------------------------


def _bypasses() -> list[tuple[str, str, str, str]]:
    """(template, gate, stage, outcome) for every edge that enters a gate."""
    out = []
    for name in NAMES:
        data = TEMPLATES[name]
        for gate in _dominating(data):
            out += [(name, gate, sid, oc) for sid, oc in _incoming(data, gate)]
    return out


BYPASSES = _bypasses()


@pytest.mark.parametrize(("name", "gate", "sid", "outcome"), BYPASSES)
def test_G2_mutation_sending_an_edge_past_a_gate_fails(
    name: str, gate: str, sid: str, outcome: str
) -> None:
    data = copy.deepcopy(TEMPLATES[name])
    onward = data["stages"][gate]["next"]["approved"]
    onward = onward if isinstance(onward, str) else onward["to"]
    _retarget(data["stages"][sid], outcome, onward)
    assert issues_of(data), f"{sid}.{outcome} now skips {gate} and nothing noticed"


def test_G2_the_bypass_mutations_are_not_empty() -> None:
    assert len(BYPASSES) >= 20
    assert {b[0] for b in BYPASSES} == set(NAMES)


# --- mutation: delete a gate -------------------------------------------------------------------


GATES = [(name, gate) for name in NAMES for gate in _dominating(TEMPLATES[name])]


@pytest.mark.parametrize(("name", "gate"), GATES)
def test_G2_mutation_splicing_a_gate_out_fails(name: str, gate: str) -> None:
    """Remove the gate stage and send everything that entered it to where it approved to."""
    data = copy.deepcopy(TEMPLATES[name])
    onward = data["stages"][gate]["next"]["approved"]
    onward = onward if isinstance(onward, str) else onward["to"]
    for sid, outcome in _incoming(data, gate):
        _retarget(data["stages"][sid], outcome, onward)
    del data["stages"][gate]
    if data["start"] == gate:
        data["start"] = onward
    assert issues_of(data), f"{gate} was deleted from {name} and nothing noticed"


@pytest.mark.parametrize(("name", "gate"), GATES)
def test_G2_mutation_a_gate_that_cannot_approve_fails(name: str, gate: str) -> None:
    data = copy.deepcopy(TEMPLATES[name])
    del data["stages"][gate]["next"]["approved"]
    assert issues_of(data), f"{gate} has no approved edge in {name} and nothing noticed"


# --- mutation: unlist a gate ------------------------------------------------------------------


def _gated_effects() -> list[tuple[str, str]]:
    return [
        (name, sid)
        for name in NAMES
        for sid, st in TEMPLATES[name]["stages"].items()
        if st["kind"] == "effect" and MANIFEST.effects[st["effect"]].effect_class == "gated"
    ]


@pytest.mark.parametrize(("name", "effect"), _gated_effects())
def test_G2_mutation_listing_no_gate_on_a_gated_effect_fails(name: str, effect: str) -> None:
    data = copy.deepcopy(TEMPLATES[name])
    del data["stages"][effect]["requires_gates"]  # an empty list is refused when it is loaded
    assert issues_of(data), f"{name}.{effect} lists no gate and nothing noticed"


@pytest.mark.parametrize("name", NAMES)
def test_G2_mutation_a_merge_that_does_not_list_the_review_gate_fails(name: str) -> None:
    data = copy.deepcopy(TEMPLATES[name])
    merge = data["stages"]["merge"]
    kept = [g for g in merge["requires_gates"] if g != "review_gate"]
    if kept:
        merge["requires_gates"] = kept
    else:
        del merge["requires_gates"]
    assert issues_of(data), f"{name}.merge lost review_gate and nothing noticed"


# --- mutation: a gate's approval is the only way through --------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_G2_mutation_a_gate_that_leads_to_a_gated_effect_on_rejection_fails(name: str) -> None:
    data = copy.deepcopy(TEMPLATES[name])
    gated = next(
        sid
        for sid, st in data["stages"].items()
        if st["kind"] == "effect" and st["effect"] == "pr.merge"
    )
    review = data["stages"]["review_gate"]
    review["next"]["rejected"] = gated
    assert issues_of(data), "a rejection that merges is a path around the approval"
