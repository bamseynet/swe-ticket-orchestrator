"""D2-18: the agent profile manifest and effect catalog, as data the validator reads."""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

import pytest

from sto.config import manifest
from sto.config.manifest import Manifest, ManifestError, load_manifest, parse_manifest
from sto.config.schema import EFFECT_OUTCOMES, Effect, ModelTier

ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mf() -> Manifest:
    return load_manifest()


def _roster_rows() -> dict[str, str]:
    """Stage -> raw 'Workers' cell of the PLAN 8.3 table."""
    section = PLAN.split("### 8.3 Roster and permissions")[1].split("**Never available")[0]
    rows = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 5 and cells[0].startswith("`"):
            rows[cells[0].strip("`")] = cells[2]
    return rows


def test_every_worker_in_plan_83_is_listed(mf: Manifest) -> None:
    rows = _roster_rows()
    assert set(rows) >= {"triage", "refine", "plan", "implement", "llm_review", "qa_agentic"}
    for stage, cell in rows.items():
        for worker in re.findall(r"`([a-z_]+)`", cell):
            assert worker in mf.profiles, f"{worker} ({stage}) missing from profiles.yaml"


def test_every_orchestrator_in_plan_83_is_listed(mf: Manifest) -> None:
    for name in ("triage", "refiner", "planner", "implementer", "qa_agent", "notifier"):
        assert mf.profiles[name].role == "orchestrator"


@pytest.mark.parametrize(
    ("name", "tier"),
    [
        ("triage", "fast"),
        ("notifier", "fast"),
        ("refiner", "standard"),
        ("qa_agent", "standard"),
        ("planner", "deep"),
        ("implementer", "deep"),
        ("coder", "standard"),
        ("test_writer", "standard"),
        ("fixer", "standard"),
        ("correctness_reviewer", "deep"),
        ("security_reviewer", "deep"),
        ("test_reviewer", "standard"),
        ("compliance_reviewer", "deep"),
    ],
)
def test_default_tier_matches_plan(mf: Manifest, name: str, tier: str) -> None:
    assert mf.profiles[name].default_tier == tier


def test_tiers_are_valid_model_tiers(mf: Manifest) -> None:
    assert {p.default_tier for p in mf.profiles.values()} <= set(get_args(ModelTier))


def test_orchestrator_outcomes(mf: Manifest) -> None:
    assert mf.agent_outcomes("triage") == frozenset({"ready", "needs_info", "not_actionable"})
    assert mf.agent_outcomes("refiner") == frozenset({"ready", "needs_info"})
    assert mf.agent_outcomes("implementer") == frozenset({"ready", "blocked"})
    assert mf.agent_outcomes("qa_agent") == frozenset({"pass", "fail", "inconclusive"})
    with pytest.raises(KeyError):
        mf.agent_outcomes("nobody")


def test_tools_are_cumulative_per_plan(mf: Manifest) -> None:
    triage = mf.tools("triage")
    assert triage == frozenset({"ticket.read", "ticket.search_similar", "repo.tree", "memory.read"})
    refiner = mf.tools("refiner")
    assert triage < refiner
    assert {"repo.read_file", "repo.search", "ask_human"} <= refiner
    planner = mf.tools("planner")
    assert refiner < planner
    assert {"repo.log", "repo.blame", "record_plan"} <= planner
    impl = mf.tools("implementer")
    assert planner < impl
    assert {"workspace.read", "workspace.write", "workspace.exec", "workspace.diff"} <= impl
    assert mf.tools("notifier") == frozenset()
    assert "browser.*" in mf.tools("qa_agent")


def test_no_agent_has_a_forbidden_tool(mf: Manifest) -> None:
    forbidden = re.compile(
        r"^(gate|merge|task_token|ticket\.(transition|comment|write)|credential|config\.write"
        r"|github\.write|jira\.write|slack\.write|pr\.(merge|mark_ready|create|ensure_draft))"
    )
    for name, profile in mf.profiles.items():
        for tool in profile.tools:
            assert not forbidden.match(tool), f"{name} has {tool}"


def test_only_implement_stage_profiles_write_workspaces(mf: Manifest) -> None:
    writers = {n for n, p in mf.profiles.items() if "workspace.write" in p.tools}
    assert writers == {"implementer", "coder", "test_writer", "fixer"}


def test_workers_never_exceed_their_orchestrator(mf: Manifest) -> None:
    for profile in mf.profiles.values():
        if profile.role == "worker" and profile.orchestrator != "review_panel":
            assert profile.orchestrator is not None
            assert profile.tools <= mf.profiles[profile.orchestrator].tools


def test_unknown_key_and_bad_tier_refused() -> None:
    with pytest.raises(ManifestError, match="tier"):
        parse_manifest(
            "profiles:\n  x: {role: orchestrator, default_tier: huge, tools: [], outcomes: [a]}\n",
            "effects: {}\n",
        )
    with pytest.raises(ManifestError):
        parse_manifest(
            "profiles:\n  x: {role: orchestrator, default_tier: fast, tools: [], outcomes: [a],"
            " auto_approve: true}\n",
            "effects: {}\n",
        )


def test_duplicate_key_refused() -> None:
    with pytest.raises(ManifestError, match="duplicate"):
        parse_manifest("profiles: {}\nprofiles: {}\n", "effects: {}\n")


# --- the effect catalog ---------------------------------------------------------------------


def test_catalog_lists_every_effect_in_the_schema(mf: Manifest) -> None:
    assert set(mf.effects) == set(get_args(Effect))


def test_plan_effect_classes(mf: Manifest) -> None:
    cls = {n: e.effect_class for n, e in mf.effects.items()}
    assert cls["branch.push"] == "exposing"
    assert cls["pr.ensure_draft"] == "scoped"
    assert cls["pr.update_branch"] == "scoped"
    assert cls["pr.open_revert"] == "scoped"
    for gated in (
        "branch.promote",
        "env.deploy_preview",
        "pr.mark_ready",
        "pr.merge",
        "ticket.transition",
        "release.trigger",
    ):
        assert cls[gated] == "gated"
    assert [n for n, c in cls.items() if c == "exposing"] == ["branch.push"]


def test_plan_effect_outcomes(mf: Manifest) -> None:
    assert mf.effects["pr.merge"].outcomes == frozenset({"done", "conflict", "stale"})
    assert mf.effects["pr.update_branch"].outcomes == frozenset({"done", "conflict"})
    assert mf.effects["release.trigger"].outcomes == frozenset({"done", "stale"})
    assert mf.effects["pr.ensure_draft"].outcomes == frozenset({"done"})


def test_key_scopes(mf: Manifest) -> None:
    assert mf.effects["pr.ensure_draft"].key_scope == ("run", "branch")
    assert mf.effects["pr.open_revert"].key_scope == ("run", "merge_sha")
    assert mf.effects["pr.merge"].key_scope == ("run", "stage", "visit", "subject")
    assert mf.effects["release.trigger"].key_scope == ("run", "stage", "visit", "subject")


def test_with_is_typed_and_closed(mf: Manifest) -> None:
    merge = mf.effects["pr.merge"].with_keys
    assert merge["method"].values == ("squash", "merge", "rebase")
    assert merge["method"].required is False
    assert "auto_approve" not in merge
    rel = mf.effects["release.trigger"].with_keys
    assert rel["workflow"].required
    assert rel["sha_input"].required
    assert set(mf.effects["ticket.transition"].with_keys) == {"to_status_category"}
    assert mf.effects["ticket.transition"].with_keys["to_status_category"].values == (
        "todo",
        "in_progress",
        "done",
    )
    assert mf.effects["branch.push"].with_keys == {}


def test_with_cannot_carry_a_hold(mf: Manifest) -> None:
    for name, effect in mf.effects.items():
        assert not {"hold", "hold_after_approval", "delay"} & set(effect.with_keys), name


def test_hold_defaults(mf: Manifest) -> None:
    assert mf.effects["pr.merge"].hold_default_seconds == 600
    assert mf.effects["release.trigger"].hold_default_seconds == 600
    assert mf.effects["pr.ensure_draft"].hold_default_seconds == 0
    for effect in mf.effects.values():
        if effect.effect_class != "gated":
            assert effect.hold_default_seconds == 0


def test_effect_outcomes_constant_is_in_sync(mf: Manifest) -> None:
    manifest.check_effect_outcomes_in_sync(mf)  # does not raise
    for name, effect in mf.effects.items():
        assert EFFECT_OUTCOMES.get(name, frozenset({"done"})) == effect.outcomes, name


def test_sync_check_detects_drift(mf: Manifest) -> None:
    drifted = {**EFFECT_OUTCOMES, "pr.merge": frozenset({"done"})}
    with pytest.raises(ManifestError, match="pr.merge"):
        manifest.check_effect_outcomes_in_sync(mf, drifted)
    extra = {**EFFECT_OUTCOMES, "pr.ensure_draft": frozenset({"done", "conflict"})}
    with pytest.raises(ManifestError, match="pr.ensure_draft"):
        manifest.check_effect_outcomes_in_sync(mf, extra)
    ghost = {**EFFECT_OUTCOMES, "not.an_effect": frozenset({"done"})}
    with pytest.raises(ManifestError, match="not.an_effect"):
        manifest.check_effect_outcomes_in_sync(mf, ghost)


def test_manifest_is_read_only(mf: Manifest) -> None:
    with pytest.raises((TypeError, AttributeError)):
        mf.profiles["triage"] = mf.profiles["refiner"]  # type: ignore[index]
