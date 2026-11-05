"""G2, static dominance (PLAN 15.3): V4 and V5 on every template, and mutation.

``test_integrity`` proves at run time that nothing gated runs before approval (G1). This proves
it before any run exists: on the stage graph of each template, a gated effect is unreachable
once any gate it lists has its approval edge removed. The mutation tests then break each
template in every way a team could (skip a gate, splice it out, list no gate, take away its
way out) and require the validator to say so. A validator that passed everything would fail
all of them.

"All templates" is the standard template and the three PLAN overlays on it, flattened, plus every
YAML file under ``templates/`` once that directory exists (D2-05), found by ``discover``. Gates
that no gated effect lists are not mutated: ``pre_push_gate`` is V16's, and ``change_gate``, the
route-conditional gate an org requires of the regulated team, is V17's.
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


def _ref_name(ref: str) -> str:
    return ref.split("@", 1)[0]


def _flatten_all(docs: list[tuple[str, Any]]) -> dict[str, dict[str, Any]]:
    """Templates by name from loaded documents: a Workflow as it is, an overlay flattened onto the
    Workflow it extends (which must be among the documents)."""
    bases = {d.metadata.name: d for _, d in docs if isinstance(d, Workflow)}
    out = {name: _dump(wf) for name, wf in ((n, bases[n]) for n in bases)}
    for label, doc in docs:
        if isinstance(doc, WorkflowOverlay):
            base = bases[_ref_name(doc.extends)]
            out[doc.metadata.name or label] = _dump(
                flatten(base, doc, template_ref=doc.extends).workflow
            )
    return out


def discover(root: Path) -> dict[str, dict[str, Any]]:
    """Every Workflow and WorkflowOverlay file under ``root``, as flattened dicts by name.
    Overlays may extend a Workflow found anywhere in ``root`` or the PLAN's standard template."""
    docs: list[tuple[str, Any]] = [
        (str(f.relative_to(root)), load_document(f.read_text(encoding="utf-8"), source=str(f)))
        for f in sorted(root.rglob("*.yaml"))
    ]
    docs = [(n, d) for n, d in docs if isinstance(d, (Workflow, WorkflowOverlay))]
    if not any(isinstance(d, Workflow) and d.metadata.name == "standard" for _, d in docs):
        docs.append(("PLAN", _plan_standard()))
    return _flatten_all(docs)


def _plan_standard() -> Workflow:
    return _load(yaml.safe_load(next(b for b in _blocks() if "kind: Workflow\n" in b)))


def _templates() -> dict[str, dict[str, Any]]:
    docs: list[tuple[str, Any]] = [("PLAN", _plan_standard())]
    for text in _blocks():
        if "kind: WorkflowOverlay" in text:
            docs.append(("PLAN", load_document(text)))
    out = _flatten_all(docs)
    shipped = ROOT / "templates"
    if shipped.is_dir():
        out |= {f"templates/{k}": v for k, v in discover(shipped).items() if k not in out}
    return out


def _dump(wf: Workflow) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(wf.model_dump_json(exclude_unset=True, by_alias=True))
    return data


TEMPLATES = _templates()
NAMES = sorted(TEMPLATES)


def issues_of(data: dict[str, Any]) -> list[str]:
    return [i.message for i in check_gate_dominance(_load(data), MANIFEST)]


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
    assert {"ledger-regulated", "payments-scrum", "platform-kanban", "standard"} <= set(NAMES)


def test_G2_discovery_picks_up_every_workflow_and_overlay_file_under_a_directory(
    tmp_path: Path,
) -> None:
    std = yaml.safe_load(next(b for b in _blocks() if "kind: Workflow\n" in b))
    std["metadata"]["name"] = "shipped"
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "shipped.yaml").write_text(yaml.safe_dump(std))
    overlay = {
        "apiVersion": "sto/v1",
        "kind": "WorkflowOverlay",
        "metadata": {"name": "shipped-fast", "team": "t"},
        "extends": "shipped@1",
        "intake": {"source": "jira", "project": "PAY", "label": "agent-ready"},
        "repo": {"name": "example/payments", "base": "main", "sandbox_image": "java21"},
        "stages": {"ci": {"timeout": "30m"}},
    }
    (tmp_path / "shipped-fast.yaml").write_text(yaml.safe_dump(overlay))
    (tmp_path / "README.md").write_text("not a template")
    found = discover(tmp_path)
    assert {"shipped", "shipped-fast"} <= set(found)
    assert found["shipped-fast"]["stages"]["ci"]["timeout"] == "30m"
    assert issues_of(found["shipped"]) == []


def test_G2_an_empty_directory_discovers_only_the_plan_standard_template(tmp_path: Path) -> None:
    assert set(discover(tmp_path)) == {"standard"}


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
    # V4 names the gate whose approval the path no longer needs; V5 alone would not be enough
    assert any(
        i.startswith("V4:") and f"without {gate}'s approval" in i for i in issues_of(data)
    ), f"{sid}.{outcome} now skips {gate} and V4 did not say so"


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
    assert any(
        i.startswith("V4:") and f"lists {gate}" in i and "does not exist" in i
        for i in issues_of(data)
    ), f"{gate} was deleted from {name} and V4 did not name it"


@pytest.mark.parametrize(("name", "gate"), GATES)
def test_G2_mutation_a_gate_that_cannot_approve_fails(name: str, gate: str) -> None:
    data = copy.deepcopy(TEMPLATES[name])
    del data["stages"][gate]["next"]["approved"]
    assert any(
        i.startswith("V4:") and f"gate {gate} has no approved edge" in i for i in issues_of(data)
    ), f"{gate} has no approved edge in {name} and V4 did not name it"


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
    assert any(
        i.startswith("V4:") and f"{effect} (" in i and "lists no gate" in i for i in issues_of(data)
    ), f"{name}.{effect} lists no gate and V4 did not name it"


@pytest.mark.parametrize("name", NAMES)
def test_G2_mutation_a_merge_that_does_not_list_the_review_gate_fails(name: str) -> None:
    data = copy.deepcopy(TEMPLATES[name])
    merge = data["stages"]["merge"]
    kept = [g for g in merge["requires_gates"] if g != "review_gate"]
    if kept:
        merge["requires_gates"] = kept
    else:
        del merge["requires_gates"]
    assert any(
        i.startswith("V6:") and "merge" in i and "review gate" in i for i in issues_of(data)
    ), f"{name}.merge lost review_gate and V6 did not say so"


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
    assert any(
        i.startswith("V4:") and "without review_gate's approval" in i for i in issues_of(data)
    ), "a rejection that merges is a path around the approval, and V4 did not say so"


# --- mutation: freshness (V5) -----------------------------------------------------------------


def _v5_cases() -> list[tuple[str, str]]:
    return [(name, effect) for name, effect in _gated_effects()]


@pytest.mark.parametrize(("name", "effect"), _v5_cases())
def test_G2_mutation_a_code_change_that_jumps_to_a_gated_effect_fails_v5(
    name: str, effect: str
) -> None:
    """``update_branch`` changes the code. Sent straight to a gated effect, the earlier
    approvals would be reused for code they never saw."""
    data = copy.deepcopy(TEMPLATES[name])
    _retarget(data["stages"]["update_branch"], "done", effect)
    assert any(
        i.startswith("V5:") and f"{effect} (" in i and "from update_branch" in i
        for i in issues_of(data)
    ), f"update_branch -> {effect} in {name} reuses an approval and V5 did not say so"
