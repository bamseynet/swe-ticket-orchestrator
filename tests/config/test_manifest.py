"""D2-18: the agent profile manifest and effect catalog, as data the validator reads."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Any, get_args

import pytest

from sto.config import manifest
from sto.config.manifest import (
    PANEL_TOOLS,
    Manifest,
    ManifestError,
    load_manifest,
    parse_manifest,
)
from sto.config.schema import EFFECT_OUTCOMES, Effect, ModelTier

ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mf() -> Manifest:
    return load_manifest()


# --- golden tables: every value of every profile and effect --------------------------------

TRIAGE = {"ticket.read", "ticket.search_similar", "repo.tree", "memory.read"}
REFINE = TRIAGE | {"repo.read_file", "repo.search", "ask_human"}
PLAN_T = REFINE | {"repo.log", "repo.blame", "record_plan"}
IMPL = PLAN_T | {"workspace.read", "workspace.write", "workspace.exec", "workspace.diff"}
WS = {"repo.tree", "repo.read_file", "repo.search"} | {
    "workspace.read",
    "workspace.write",
    "workspace.exec",
    "workspace.diff",
}
REVIEW = {"repo.read_file", "repo.search", "pr.diff", "checks.read", "record_finding"}

# name: (role, tier, orchestrator, outcomes, tools)
PROFILES: dict[str, tuple[str, str, str | None, set[str], set[str]]] = {
    "triage": ("orchestrator", "fast", None, {"ready", "needs_info", "not_actionable"}, TRIAGE),
    "refiner": ("orchestrator", "standard", None, {"ready", "needs_info"}, REFINE),
    "planner": ("orchestrator", "deep", None, {"ready", "needs_info"}, PLAN_T),
    "implementer": ("orchestrator", "deep", None, {"ready", "blocked"}, IMPL),
    "qa_agent": (
        "orchestrator",
        "standard",
        None,
        {"pass", "fail", "inconclusive"},
        {"browser.*", "code_interpreter.run", "env.info", "record_evidence", "pr.diff"},
    ),
    "notifier": ("orchestrator", "fast", None, {"done"}, set()),
    "ac_writer": (
        "worker",
        "standard",
        "refiner",
        set(),
        {"ticket.read", "repo.tree", "repo.read_file", "repo.search"},
    ),
    "ambiguity_finder": (
        "worker",
        "standard",
        "refiner",
        set(),
        {"ticket.read", "ticket.search_similar", "repo.tree", "repo.read_file", "repo.search"},
    ),
    "code_explorer": (
        "worker",
        "standard",
        "planner",
        set(),
        {"repo.tree", "repo.read_file", "repo.search", "repo.log", "repo.blame"},
    ),
    "risk_assessor": (
        "worker",
        "standard",
        "planner",
        set(),
        {"ticket.read", "repo.tree", "repo.read_file", "repo.search", "repo.log", "repo.blame"},
    ),
    "coder": ("worker", "standard", "implementer", set(), WS),
    "test_writer": ("worker", "standard", "implementer", set(), WS),
    "fixer": ("worker", "standard", "implementer", set(), WS),
    "correctness_reviewer": ("worker", "deep", "review_panel", set(), REVIEW),
    "security_reviewer": ("worker", "deep", "review_panel", set(), REVIEW),
    "test_reviewer": ("worker", "standard", "review_panel", set(), REVIEW),
    "compliance_reviewer": ("worker", "deep", "review_panel", set(), REVIEW),
    "test_planner": ("worker", "standard", "qa_agent", set(), {"env.info", "pr.diff"}),
    "explorer": (
        "worker",
        "standard",
        "qa_agent",
        set(),
        {"browser.*", "env.info", "record_evidence"},
    ),
    "verifier": (
        "worker",
        "standard",
        "qa_agent",
        set(),
        {"browser.*", "code_interpreter.run", "env.info", "record_evidence", "pr.diff"},
    ),
}

FULL = ("run", "stage", "visit", "subject")
# name: (class, outcomes, key_scope, hold seconds, {with key: (type, required, values)})
EFFECTS: dict[
    str, tuple[str, set[str], tuple[str, ...], int, dict[str, tuple[str, bool, tuple[str, ...]]]]
] = {
    "branch.push": ("exposing", {"done"}, FULL, 0, {}),
    "branch.promote": ("gated", {"done"}, FULL, 0, {}),
    "pr.ensure_draft": ("scoped", {"done"}, ("run", "branch"), 0, {}),
    "pr.update_branch": ("scoped", {"done", "conflict"}, FULL, 0, {}),
    "pr.mark_ready": ("gated", {"done"}, FULL, 0, {}),
    "pr.merge": (
        "gated",
        {"done", "conflict", "stale"},
        FULL,
        600,
        {"method": ("enum", False, ("squash", "merge", "rebase"))},
    ),
    "pr.open_revert": ("scoped", {"done"}, ("run", "merge_sha"), 0, {}),
    "ticket.comment": ("scoped", {"done"}, FULL, 0, {"template": ("ident", False, ())}),
    "ticket.transition": (
        "gated",
        {"done"},
        FULL,
        600,
        {"to_status_category": ("enum", True, ("todo", "in_progress", "done"))},
    ),
    "env.deploy_preview": ("gated", {"done"}, FULL, 0, {}),
    "release.trigger": (
        "gated",
        {"done", "stale"},
        FULL,
        600,
        {"workflow": ("text", True, ()), "sha_input": ("ident", True, ())},
    ),
    "notify": ("scoped", {"done"}, FULL, 0, {"template": ("ident", False, ())}),
}


def test_golden_profiles(mf: Manifest) -> None:
    assert set(mf.profiles) == set(PROFILES)
    for name, (role, tier, boss, outcomes, tools) in PROFILES.items():
        p = mf.profiles[name]
        assert (p.role, p.default_tier, p.orchestrator) == (role, tier, boss), name
        assert p.outcomes == frozenset(outcomes), name
        assert p.tools == frozenset(tools), name


def test_golden_effects(mf: Manifest) -> None:
    assert set(mf.effects) == set(EFFECTS)
    for name, (cls, outcomes, scope, hold, withs) in EFFECTS.items():
        e = mf.effects[name]
        assert e.effect_class == cls, name
        assert e.outcomes == frozenset(outcomes), name
        assert e.key_scope == scope, name
        assert e.hold_seconds == hold, name
        got = {k: (w.type, w.required, w.values) for k, w in e.with_keys.items()}
        assert got == withs, name


def test_catalog_lists_every_effect_in_the_schema(mf: Manifest) -> None:
    assert set(mf.effects) == set(get_args(Effect))


def test_tiers_are_valid_model_tiers(mf: Manifest) -> None:
    assert {p.default_tier for p in mf.profiles.values()} <= set(get_args(ModelTier))


def test_nothing_in_with_can_change_a_gate_or_a_hold(mf: Manifest) -> None:
    banned = {"hold", "hold_seconds", "hold_after_approval", "delay", "auto_approve", "auto_merge"}
    for name, effect in mf.effects.items():
        assert not banned & set(effect.with_keys), name


def test_no_agent_has_a_write_or_authority_tool(mf: Manifest) -> None:
    forbidden = re.compile(
        r"^(gate|merge|task_token|credential|secrets|config|github|jira|slack|branch|release"
        r"|env\.deploy|ticket\.(transition|comment|write)|pr\.(?!diff$))"
    )
    for name, profile in mf.profiles.items():
        for tool in profile.tools:
            assert not forbidden.match(tool), f"{name} has {tool}"


def test_only_implement_stage_profiles_write_workspaces(mf: Manifest) -> None:
    writers = {n for n, p in mf.profiles.items() if "workspace.write" in p.tools}
    assert writers == {"implementer", "coder", "test_writer", "fixer"}
    execs = {n for n, p in mf.profiles.items() if "workspace.exec" in p.tools}
    assert execs == writers


# --- PLAN 8.3 is the source: compare in both directions ------------------------------------

_HEADERS = ["Stage", "Orchestrator", "Workers", "Tools", "Sandbox"]


def _roster() -> list[dict[str, Any]]:
    assert PLAN.count("### 8.3 Roster and permissions") == 1
    section = PLAN.split("### 8.3 Roster and permissions")[1].split("**Never available")[0]
    lines = [ln for ln in section.splitlines() if ln.startswith("|")]
    header = [c.strip() for c in lines[0].strip().strip("|").split("|")]
    assert header == _HEADERS
    assert set(lines[1].replace("|", "").strip()) <= {"-"}
    rows = []
    for ln in lines[2:]:
        assert "\\|" not in ln, "an escaped pipe would shift the columns"
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        assert len(cells) == 5, ln
        rows.append(dict(zip(_HEADERS, cells, strict=True)))
    assert len(rows) == 7
    return rows


def _orchestrator(cell: str) -> str:
    if cell.startswith("Panel"):
        return "review_panel"
    name = re.sub(r"\s*\(.*\)", "", cell).strip().lower()
    return name.replace(" ", "_")


def test_stage_to_worker_sets_match_plan_exactly(mf: Manifest) -> None:
    plan: dict[str, set[str]] = {}
    for row in _roster():
        plan[_orchestrator(row["Orchestrator"])] = set(
            re.findall(r"`([a-z0-9_]+)`", row["Workers"])
        )
    assert set(plan) == {
        "triage",
        "refiner",
        "planner",
        "implementer",
        "review_panel",
        "qa_agent",
        "notifier",
    }
    assert plan["triage"] == set()
    assert plan["notifier"] == set()
    for boss, workers in plan.items():
        have = {n for n, p in mf.profiles.items() if p.role == "worker" and p.orchestrator == boss}
        assert have == workers, boss
    assert {n for n, p in mf.profiles.items() if p.role == "orchestrator"} == set(plan) - {
        "review_panel"
    }


def test_orchestrator_tools_and_tiers_match_plan(mf: Manifest) -> None:
    previous: set[str] = set()
    for row in _roster():
        boss = _orchestrator(row["Orchestrator"])
        cell = row["Tools"]
        found = set(re.findall(r"`([^`]+)`", cell))
        if cell.startswith(("Above", "Refine tools", "Plan tools")):
            found |= previous
        if boss == "review_panel":
            assert found == PANEL_TOOLS
            continue
        assert mf.tools(boss) == frozenset(found), boss
        previous = found
        tier = re.search(r"\((fast|standard|deep)\)", row["Orchestrator"])
        assert tier is not None
        assert mf.default_tier(boss) == tier[1], boss


def test_worker_tiers_stated_in_plan(mf: Manifest) -> None:
    for row in _roster():
        for name, tier in re.findall(r"`([a-z0-9_]+)` \((fast|standard|deep)\)", row["Workers"]):
            assert mf.default_tier(name) == tier, name


# --- the API -------------------------------------------------------------------------------


def test_api_methods(mf: Manifest) -> None:
    assert mf.agent_outcomes("triage") == frozenset({"ready", "needs_info", "not_actionable"})
    assert mf.default_tier("planner") == "deep"
    assert mf.default_tier("coder") == "standard"
    assert mf.effect_outcomes("pr.merge") == frozenset({"done", "conflict", "stale"})
    assert mf.tools("notifier") == frozenset()
    with pytest.raises(KeyError, match="worker"):
        mf.agent_outcomes("coder")
    with pytest.raises(KeyError):
        mf.agent_outcomes("nobody")
    with pytest.raises(KeyError):
        mf.default_tier("nobody")
    with pytest.raises(KeyError):
        mf.effect_outcomes("not.an_effect")


def test_the_manifest_is_read_only(mf: Manifest) -> None:
    with pytest.raises(TypeError):
        mf.profiles["triage"] = mf.profiles["refiner"]  # type: ignore[index]
    with pytest.raises(TypeError):
        mf.effects["pr.merge"].with_keys["hold_seconds"] = None  # type: ignore[index]
    with pytest.raises(TypeError):
        del mf.effects["pr.merge"].with_keys["method"]  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        mf.profiles["triage"].tools.add("x")  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="frozen"):
        mf.effects["pr.merge"].hold_seconds = 0


def test_the_dump_serialises_and_is_stable(mf: Manifest) -> None:
    text = mf.model_dump_json()
    assert json.loads(text) == mf.model_dump(mode="json")
    assert mf.model_dump_json() == text
    data = json.loads(text)
    assert data["profiles"]["triage"]["tools"] == sorted(TRIAGE)
    assert data["effects"]["pr.merge"]["with_keys"]["method"]["values"] == [
        "squash",
        "merge",
        "rebase",
    ]
    for prof in data["profiles"].values():
        assert prof["tools"] == sorted(prof["tools"])
        assert prof["outcomes"] == sorted(prof["outcomes"])
    for eff in data["effects"].values():
        assert eff["outcomes"] == sorted(eff["outcomes"])
    assert list(data["profiles"]) == sorted(data["profiles"])
    assert list(data["effects"]) == sorted(data["effects"])


def test_the_dump_does_not_depend_on_file_order() -> None:
    root = resources.files("sto.catalog")
    profiles = root.joinpath("profiles.yaml").read_text(encoding="utf-8")
    effects = root.joinpath("effects.yaml").read_text(encoding="utf-8")
    reordered = "profiles:\n" + "\n".join(
        reversed(re.split(r"\n(?=  [a-z_]+:\n)", profiles.split("profiles:\n", 1)[1]))
    )
    a = parse_manifest(profiles, effects).model_dump_json()
    b = parse_manifest(reordered, effects).model_dump_json()
    assert a == b


# --- packaging -----------------------------------------------------------------------------


def test_catalog_files_ship_inside_the_package() -> None:
    root = resources.files("sto.catalog")
    for name in ("profiles.yaml", "effects.yaml"):
        assert root.joinpath(name).is_file(), name
    src = ROOT / "src" / "sto" / "catalog"
    assert {p.name for p in src.glob("*.yaml")} == {"profiles.yaml", "effects.yaml"}
    assert (src / "__init__.py").is_file()
    assert not (ROOT / "catalog").exists()


def test_the_build_does_not_exclude_catalog_files() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'build-backend = "uv_build"' in pyproject
    assert "source-exclude" not in pyproject
    assert "wheel-exclude" not in pyproject


# --- refusals, through parse_manifest ------------------------------------------------------

GOOD_EFFECT = "  e.x: {class: scoped, outcomes: [done], key_scope: [run], hold: 0s, with: {}}\n"
GOOD_EFFECTS = "effects:\n" + GOOD_EFFECT


def _orch(name: str = "boss", extra: str = "") -> str:
    head = f"  {name}: {{role: orchestrator, default_tier: fast"
    return f"{head}, outcomes: [a], tools: [x.y]{extra}}}\n"


def _worker(name: str = "w", tools: str = "x.y", boss: str = "boss") -> str:
    return (
        f"  {name}: {{role: worker, orchestrator: {boss}, default_tier: fast, tools: [{tools}]}}\n"
    )


def _refused(profiles: str, effects: str = GOOD_EFFECTS) -> list[str]:
    with pytest.raises(ManifestError) as err:
        parse_manifest(profiles, effects)
    return err.value.problems


def test_a_minimal_catalog_parses() -> None:
    got = parse_manifest("profiles:\n" + _orch() + _worker(), GOOD_EFFECTS)
    assert set(got.profiles) == {"boss", "w"}


def test_a_bad_tier_names_the_file_and_the_profile() -> None:
    problems = _refused("profiles:\n" + _orch().replace("fast", "huge"))
    assert len(problems) == 1
    assert problems[0].startswith("profiles.yaml: boss.default_tier")


def test_unknown_keys_are_refused() -> None:
    assert _refused("profiles:\n" + _orch(extra=", auto_approve: true"))
    assert _refused("profiles:\n" + _orch(), GOOD_EFFECTS.replace("hold: 0s", "hold: 0s, free: 1"))


def test_every_problem_in_both_files_is_reported() -> None:
    bad_profiles = "profiles:\n" + _orch().replace("fast", "huge") + _worker("w2", boss="ghost")
    bad_effects = GOOD_EFFECTS.replace("scoped", "weird")
    with pytest.raises(ManifestError) as err:
        parse_manifest(bad_profiles, bad_effects, profiles_file="p.yaml", effects_file="e.yaml")
    files = {p.split(":")[0] for p in err.value.problems}
    assert files == {"p.yaml", "e.yaml"}
    assert str(err.value).count("\n") == len(err.value.problems) - 1


def test_cross_checks_report_every_problem() -> None:
    problems = _refused(
        "profiles:\n" + _orch() + _worker("a", tools="x.z") + _worker("b", boss="ghost")
    )
    assert len(problems) == 2


def test_duplicate_key_is_refused_with_a_line() -> None:
    problems = _refused("profiles: {}\nprofiles: {}\n")
    assert problems == ["profiles.yaml: line 2: duplicate key 'profiles'"]


def test_an_unhashable_key_is_a_manifest_error() -> None:
    assert "profiles.yaml: line 2" in _refused("profiles:\n  ? [a, b]\n  : 1\n")[0]


def test_only_safe_yaml_loads() -> None:
    problems = _refused("profiles: !!python/object/apply:os.getcwd []\n")
    assert "not valid YAML" in problems[0]


def test_the_document_shape_is_checked() -> None:
    assert "single key 'profiles'" in _refused("effects: {}\n")[0]
    assert "single key 'profiles'" in _refused("[1, 2]\n")[0]
    assert "single key 'profiles'" in _refused("profiles: [1]\n")[0]
    assert "not valid YAML" in _refused("profiles: [\n")[0]


def test_a_worker_may_not_exceed_its_orchestrator() -> None:  # the rule, on a bad input
    problems = _refused("profiles:\n" + _orch() + _worker(tools="x.y, secrets.read"))
    assert problems == ["profiles.yaml: w: tools ['secrets.read'] are not in boss's allowlist"]


def test_a_worker_needs_a_real_orchestrator() -> None:
    assert "'ghost' is not an orchestrator" in _refused("profiles:\n" + _worker(boss="ghost"))[0]
    chain = "profiles:\n" + _orch() + _worker("w1") + _worker("w2", boss="w1")
    assert "'w1' is not an orchestrator" in _refused(chain)[0]


def test_role_fields_are_checked() -> None:
    assert _refused("profiles:\n  b: {role: orchestrator, default_tier: fast, tools: []}\n")
    assert _refused("profiles:\n" + _orch(extra=", orchestrator: z"))
    assert _refused(
        "profiles:\n" + _orch("b") + "  w: {role: worker, orchestrator: b, default_tier: fast,"
        " outcomes: [a], tools: []}\n"
    )
    assert _refused("profiles:\n  w: {role: worker, default_tier: fast, tools: []}\n")


def _panel(name: str, tools: str) -> str:
    return _worker(name, tools=tools, boss="review_panel")


def test_a_panel_worker_holds_only_the_panel_tools() -> None:
    ok = "repo.read_file, record_finding"
    assert parse_manifest("profiles:\n" + _panel("r", ok), GOOD_EFFECTS)
    for extra in ("secrets.read", "workspace.exec", "ask_human", "github.merge", "workspace.write"):
        problems = _refused("profiles:\n" + _panel("r", f"{ok}, {extra}"))
        assert any("may not hold" in p and extra in p for p in problems), extra


def test_a_panel_worker_must_record_findings() -> None:
    problems = _refused("profiles:\n" + _panel("r", "repo.read_file"))
    assert any("must hold record_finding" in p for p in problems)


def test_a_coder_cannot_pass_as_a_panel_worker() -> None:
    problems = _refused("profiles:\n" + _panel("coder", "workspace.write, record_finding"))
    assert any("workspace.write" in p for p in problems)


def test_review_panel_is_not_a_profile_name() -> None:
    assert any("stage kind" in p for p in _refused("profiles:\n" + _orch("review_panel")))


def test_panel_tools_match_plan_llm_review_row() -> None:
    row = next(r for r in _roster() if r["Stage"] == "`llm_review`")
    assert set(re.findall(r"`([^`]+)`", row["Tools"])) == PANEL_TOOLS


def test_duplicate_tools_outcomes_and_values_are_refused() -> None:
    assert _refused("profiles:\n" + _orch().replace("[x.y]", "[x.y, x.y]"))
    assert _refused("profiles:\n" + _orch().replace("[a]", "[a, a]"))
    twice = GOOD_EFFECTS.replace("[done]", "[done, done]")
    assert _refused("profiles:\n" + _orch(), twice)
    enum = GOOD_EFFECTS.replace("with: {}", "with: {k: {type: enum, values: [a, a]}}")
    assert _refused("profiles:\n" + _orch(), enum)


def test_wildcards_are_only_for_browser() -> None:
    assert parse_manifest("profiles:\n" + _orch().replace("x.y", "browser.*"), GOOD_EFFECTS)
    for bad in ("github.*", "workspace.*", "*"):
        assert _refused("profiles:\n" + _orch().replace("x.y", bad)), bad


def test_tool_names_are_checked() -> None:
    for bad in ("X.y", "x..y", "x.y\n", "x y", ""):
        assert _refused("profiles:\n" + _orch().replace("x.y", f"'{bad}'")), repr(bad)


def test_effect_rules() -> None:
    def one(old: str, new: str) -> list[str]:
        return _refused("profiles:\n" + _orch(), GOOD_EFFECTS.replace(old, new))

    assert "done outcome" in one("[done]", "[conflict]")[0]
    assert "only a gated effect has a hold" in one("hold: 0s", "hold: 10m")[0]
    assert "key_scope" in one("[run]", "[]")[0]
    assert "not a key part" in one("[run]", "[run, nonsense]")[0]
    assert "listed twice" in one("[run]", "[run, run]")[0]
    for bad in ("10m\n", "10", "m", "1.5h", "-1s", "10 m", "0"):
        assert "hold must be a duration" in one("hold: 0s", f'hold: "{bad}"')[0], repr(bad)
    assert "hold must be a duration" in one("hold: 0s", "hold: 0")[0]
    assert one("class: scoped", "class: gated, free: 1")


def test_gated_holds_parse_every_unit() -> None:
    for text, seconds in (("5s", 5), ("2m", 120), ("3h", 10800), ("1d", 86400), ("0s", 0)):
        effects = GOOD_EFFECTS.replace("scoped", "gated").replace("hold: 0s", f"hold: {text}")
        got = parse_manifest("profiles:\n" + _orch(), effects)
        assert got.effects["e.x"].hold_seconds == seconds


def test_with_key_rules() -> None:
    def with_(spec: str) -> list[str]:
        return _refused(
            "profiles:\n" + _orch(), GOOD_EFFECTS.replace("with: {}", f"with: {{k: {spec}}}")
        )

    assert "values are required" in with_("{type: enum}")[0]
    assert "values are required" in with_("{type: text, values: [a]}")[0]
    assert with_("{type: number}")
    assert with_("{type: text, required: yes_please}")
    assert with_("{type: text, extra: 1}")


def test_names_are_checked() -> None:
    assert _refused("profiles:\n" + _orch("Boss"))
    assert _refused("profiles:\n" + _orch(), GOOD_EFFECTS.replace("e.x", "E.x"))


def test_a_catalog_effect_has_no_stringly_typed_bools() -> None:
    effects = GOOD_EFFECTS.replace("with: {}", "with: {k: {type: text, required: 'true'}}")
    assert _refused("profiles:\n" + _orch(), effects)


# --- the sync check ------------------------------------------------------------------------


def test_effect_outcomes_constant_is_in_sync(mf: Manifest) -> None:
    manifest.check_effect_outcomes_in_sync(mf)
    for name, effect in mf.effects.items():
        assert EFFECT_OUTCOMES.get(name, frozenset({"done"})) == effect.outcomes, name


def test_sync_check_detects_drift(mf: Manifest) -> None:
    with pytest.raises(ManifestError, match="pr.merge"):
        manifest.check_effect_outcomes_in_sync(
            mf, {**EFFECT_OUTCOMES, "pr.merge": frozenset({"done"})}
        )
    with pytest.raises(ManifestError, match="pr.ensure_draft"):
        manifest.check_effect_outcomes_in_sync(
            mf, {**EFFECT_OUTCOMES, "pr.ensure_draft": frozenset({"done", "conflict"})}
        )
    with pytest.raises(ManifestError, match="not.an_effect"):
        manifest.check_effect_outcomes_in_sync(
            mf, {**EFFECT_OUTCOMES, "not.an_effect": frozenset({"done"})}
        )
    for gone in EFFECT_OUTCOMES:  # removing any entry must be noticed: it would mean only done
        table = {k: v for k, v in EFFECT_OUTCOMES.items() if k != gone}
        with pytest.raises(ManifestError, match=re.escape(gone)):
            manifest.check_effect_outcomes_in_sync(mf, table)
