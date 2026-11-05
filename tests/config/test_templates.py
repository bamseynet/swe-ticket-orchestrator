"""D2-05: the bundled templates, run through the real loaders and validators.

``standard`` is the template; ``kanban`` and ``regulated`` are overlays on it. Nothing here
copies a validator rule: every file goes through ``load_document``, ``flatten``,
``validate_structure``, ``check_gate_dominance`` and ``check_org_required_gates``.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from bundled_templates import (
    BUNDLED,
    OVERLAY_NAMES,
    ROOT,
    SANDBOX_IMAGES,
    TEAM,
    TEMPLATE_REF,
    TEMPLATES,
    flattened,
    overlay,
    policy,
    template,
    template_file,
)

from sto.config.manifest import load_manifest
from sto.config.org_policy import check_org_required_gates, permitted_surfaces
from sto.config.overlays import flatten
from sto.config.schema import (
    GateStage,
    OrgPolicy,
    WorkflowOverlay,
    load_document,
)
from sto.config.validate_gates import check_gate_dominance
from sto.config.validate_structure import validate_structure

PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")
MANIFEST = load_manifest()
PLAN_NAME = {"standard": "standard", "kanban": "platform-kanban", "regulated": "ledger-regulated"}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _plan_blocks() -> dict[str, str]:
    section = PLAN[PLAN.index("## 7. Workflow configuration") : PLAN.index("## 8. Agents")]
    blocks = re.findall(r"```yaml\n(.*?)```", section, flags=re.S)
    docs = [b for b in blocks if "apiVersion: sto/v1" in b and ": string" not in b]
    return {
        yaml.safe_load(b)["metadata"]["name"]: b
        for b in docs
        if re.search(r"^kind: Workflow(Overlay)?\b", b, flags=re.M)
    }


PLAN_BLOCKS = _plan_blocks()


def messages(issues: list[Any]) -> str:
    return "\n".join(f"{i.path}: {i.message}" for i in issues)


# --- all validate ------------------------------------------------------------------------------


def test_the_bundle_is_exactly_the_three_templates() -> None:
    assert sorted(p.name for p in TEMPLATES.iterdir() if p.is_dir()) == sorted(BUNDLED)
    assert template().metadata.name == "standard"
    assert [overlay(n).extends for n in OVERLAY_NAMES] == [TEMPLATE_REF] * 2


@pytest.mark.parametrize("name", BUNDLED)
def test_structure_validates(name: str) -> None:
    got = validate_structure(
        flattened(name), manifest=MANIFEST, policy=policy(), sandbox_images=SANDBOX_IMAGES
    )
    assert got == [], messages(got)


@pytest.mark.parametrize("name", BUNDLED)
def test_gate_dominance_validates(name: str) -> None:
    got = check_gate_dominance(flattened(name), MANIFEST)
    assert got == [], messages(got)


@pytest.mark.parametrize("name", BUNDLED)
def test_org_required_gates_validate(name: str) -> None:
    wf = flattened(name)
    got = check_org_required_gates(wf, policy(), team=wf.metadata.team)
    assert got == [], messages(got)


@pytest.mark.parametrize("name", OVERLAY_NAMES)
def test_overlays_are_publishable_and_name_their_team(name: str) -> None:
    wf = flattened(name)
    assert wf.missing_for_publish() == []
    assert wf.metadata.team == TEAM[name]
    assert wf.metadata.name == PLAN_NAME[name]


def test_the_template_leaves_intake_and_repo_to_its_overlays() -> None:
    wf = template()
    assert wf.metadata.team == "_template"
    assert wf.missing_for_publish() != []


def test_the_regulated_overlay_is_held_to_the_orgs_extra_gates() -> None:
    """The bundled policy makes ``security_gate`` and ``change_gate`` the org's, so removing
    either from the overlay fails V17 rather than passing because the policy names nothing."""
    pol = policy()
    assert {g.id for g in pol.teams["ledger"].required_gates} == {"security_gate", "change_gate"}
    wf = flattened("regulated")
    stages = copy.deepcopy(dict(wf.stages))
    sec = stages["security_gate"]
    assert isinstance(sec, GateStage)
    stages["security_gate"] = sec.model_copy(
        update={"gate": sec.gate.model_copy(update={"eligible_roles": ("qa",)})}
    )
    weakened = wf.model_copy(update={"stages": stages})
    assert check_org_required_gates(weakened, pol, team="ledger") != []


# --- the bundled policy ------------------------------------------------------------------------


def test_the_bundled_policy_names_the_pre_push_and_custom_surfaces() -> None:
    pol = policy()
    assert permitted_surfaces(pol, "pre_push") != frozenset()
    assert permitted_surfaces(pol, "custom") != frozenset()
    gate_types = {
        st.gate.type
        for n in BUNDLED
        for st in flattened(n).stages.values()
        if isinstance(st, GateStage)
    }
    assert gate_types == {"pre_push", "review", "qa", "custom"}
    assert gate_types <= set(pol.floors.decision_surfaces)


# --- READMEs -----------------------------------------------------------------------------------


@pytest.mark.parametrize("name", BUNDLED)
def test_each_template_has_a_readme_saying_when_to_use_it_and_which_checks_to_require(
    name: str,
) -> None:
    text = _read(TEMPLATES / name / "README.md")
    headings = re.findall(r"^#{1,3} (.+)$", text, flags=re.M)
    assert any(h.lower().startswith("when to use") for h in headings), headings
    assert any(h.lower().startswith("checks to require") for h in headings), headings
    section = text[re.search(r"^#{1,3} Checks to require", text, flags=re.M | re.I).start() :]  # type: ignore[union-attr]
    # it names the real check names the workflow waits on, not a generic remark
    wf = flattened(name)
    named = {
        "sto/review-gate",
    } | {
        c
        for st in wf.stages.values()
        if getattr(st, "kind", None) == "checks"
        for c in (getattr(st, "required", None) or ())
        if c != "team_default"
    }
    for check in named:
        assert check in section, f"{name} README must name the check {check}"


def test_the_bundle_has_an_index_readme_naming_all_three() -> None:
    text = _read(TEMPLATES / "README.md")
    for name in BUNDLED:
        # a link to the folder's README or a heading for it, not a stray mention
        link = re.search(rf"\]\(\.?/?{name}/(README\.md)?\)", text)
        heading = re.search(rf"^#{{1,6}} .*\b{name}\b", text, flags=re.M)
        assert link or heading, f"templates/README.md must link to {name}/README.md"


# --- PLAN.md examples match --------------------------------------------------------------------


@pytest.mark.parametrize("name", BUNDLED)
def test_each_file_is_the_plan_example(name: str) -> None:
    assert yaml.safe_load(_read(template_file(name))) == yaml.safe_load(
        PLAN_BLOCKS[PLAN_NAME[name]]
    )


def test_the_scrum_overlay_is_not_bundled_because_it_is_a_team_example() -> None:
    """PLAN 7.6's ``payments-scrum`` is one team's overlay on ``standard`` (with its own repo,
    sprint and custom profile). Its flattening is covered in test_overlays.py; the bundle ships
    only what every later suite should run against."""
    assert "payments-scrum" in PLAN_BLOCKS
    assert not any("payments" in p.name for p in TEMPLATES.rglob("*"))


# --- the Kanban quorum -------------------------------------------------------------------------

KANBAN_QUORUM = "quorum: [{role: qa, count: 1}]"
QA_POLICY: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "OrgPolicy",
    "floors": {
        "mandatory_gate_roles": {
            "pre_push": ["reviewer"],
            "review": ["reviewer"],
            "qa": ["qa", "reviewer"],
        },
        "decision_surfaces": {
            "pre_push": ["ui"],
            "review": ["ui", "slack", "github"],
            "qa": ["ui", "slack"],
            "custom": ["ui"],
        },
        "hold_after_approval_min": "10m",
        "identity_max_age": "8h",
    },
    "teams": {"platform": {"required_gates": [{"id": "qa_gate", "role": "qa"}]}},
}


def _qa_org() -> OrgPolicy:
    doc = load_document(yaml.safe_dump(QA_POLICY))
    assert isinstance(doc, OrgPolicy)
    return doc


def test_the_kanban_readme_shows_the_qa_quorum_an_org_requiring_qa_gate_needs() -> None:
    text = _read(TEMPLATES / "kanban" / "README.md")
    assert KANBAN_QUORUM in text
    # why it matters: without it a reviewer alone can decide the QA gate
    assert "lets QA pass with no QA person" in " ".join(text.split())


def test_the_kanban_overlay_needs_that_quorum_for_an_org_requiring_qa_gate_with_role_qa() -> None:
    wf = flattened("kanban")
    qa_gate = wf.stages["qa_gate"]
    assert isinstance(qa_gate, GateStage)
    assert qa_gate.gate.eligible_roles == ("qa", "reviewer")
    without = check_org_required_gates(wf, _qa_org(), team="platform")
    assert any("qa_gate" in i.path for i in without), "the PLAN overlay has no qa quorum"

    patched = copy.deepcopy(yaml.safe_load(_read(template_file("kanban"))))
    patched["stages"]["qa_gate"]["gate"]["quorum"] = [{"role": "qa", "count": 1}]
    ov = load_document(yaml.safe_dump(patched))
    assert isinstance(ov, WorkflowOverlay)
    with_quorum = flatten(template(), ov, template_ref=TEMPLATE_REF).workflow
    got = check_org_required_gates(with_quorum, _qa_org(), team="platform")
    assert got == [], messages(got)
    assert (
        validate_structure(
            with_quorum, manifest=MANIFEST, policy=_qa_org(), sandbox_images=SANDBOX_IMAGES
        )
        == []
    )
    assert check_gate_dominance(with_quorum, MANIFEST) == []


# --- the bundled policy against PLAN's own OrgPolicy example -------------------------------------


def _leaves(value: Any, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], Any]:
    if isinstance(value, dict):
        return {k: v for key, item in value.items() for k, v in _leaves(item, (*path, key)).items()}
    return {path: value}


def _plan_policy_text() -> str:
    section = PLAN[PLAN.index("## 7. Workflow configuration") : PLAN.index("## 8. Agents")]
    blocks: list[str] = re.findall(r"```yaml\n(.*?)```", section, flags=re.S)
    return next(b for b in blocks if "kind: OrgPolicy" in b and ": string" not in b)


# every difference between PLAN 7.2's OrgPolicy example and templates/org-policy.yaml, and why
_POLICY_DIFFERENCES = {
    ("floors", "decision_surfaces", "pre_push"): "the standard template's pre_push_gate uses ui; "
    "PLAN's example names no pre_push surface, so (V10) it permits none",
    ("floors", "decision_surfaces", "custom"): "the regulated overlay's security_gate and "
    "change_gate are custom gates; PLAN's example names no custom surface",
    ("floors", "waive_allowed"): "PLAN's example allows waive; no bundled template uses it and "
    "PLAN 7.8 says the regulated org forbids it, so the bundled policy is the safer false",
    ("ceilings", "max_run_age"): "the regulated overlay's max_run_age is 90d, above PLAN's 60d "
    "ceiling (V9)",
    ("ceilings", "max_stage_duration"): "the regulated overlay's expire_after values are 20d, "
    "20d, 20d and 15d, above PLAN's 14d ceiling (V9)",
}


def test_the_bundled_policy_differs_from_plans_example_only_where_plans_own_workflows_need_it() -> (
    None
):
    """PLAN's OrgPolicy example cannot validate PLAN's own workflows, so the bundled policy
    differs from it in exactly ``_POLICY_DIFFERENCES``, each for the reason given there. Both
    are loaded through ``load_document``, so defaults are filled in on both sides and a key
    PLAN spells out at its default does not count as a difference."""
    plan = load_document(_plan_policy_text())
    assert isinstance(plan, OrgPolicy)
    a = _leaves(plan.model_dump(mode="json"))
    b = _leaves(policy().model_dump(mode="json"))
    differing = {k for k in a.keys() | b.keys() if a.get(k, "<absent>") != b.get(k, "<absent>")}
    assert differing == set(_POLICY_DIFFERENCES)


def test_plans_own_policy_refuses_the_workflows_that_need_those_differences() -> None:
    plan = load_document(_plan_policy_text())
    assert isinstance(plan, OrgPolicy)
    found: dict[str, str] = {}
    for name in BUNDLED:
        wf = flattened(name)
        for i in validate_structure(
            wf, manifest=MANIFEST, policy=plan, sandbox_images=SANDBOX_IMAGES
        ):
            found.setdefault(name, "")
            found[name] += f"\n{i.path}: {i.message}"
    assert "pre_push_gate" in found["standard"]  # no pre_push surface
    assert "custom" in found["regulated"] or "security_gate" in found["regulated"]
    assert "max_run_age" in found["regulated"]  # 90d over the 60d ceiling
    assert "expire_after" in found["regulated"]  # over the 14d max_stage_duration
