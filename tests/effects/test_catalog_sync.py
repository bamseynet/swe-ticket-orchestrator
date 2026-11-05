"""D2-03: ``STALE_EDGE_TYPES`` and ``IMPLICIT_TYPES`` in ``sto.effects.ports`` stay in step with the
effect catalog and with PLAN.md. The catalog lists the effects a workflow can name; the engine's
own effects (check runs, gate notifications, ``pr.close``) are not in it, so the test says which
names those are rather than letting a typo pass."""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

from sto.config.manifest import load_manifest
from sto.config.schema import Effect
from sto.effects.ports import IMPLICIT_TYPES, STALE_EDGE_TYPES

ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")
MANIFEST = load_manifest()

# PLAN 6.3, scoped row: "Engine-implicit, needing no stage: check runs, gate notifications,
# `pr.close` on reject, a revert PR for an unqualified merge". The revert PR is `pr.open_revert`,
# which a workflow may also declare, so it is in the catalog.
ENGINE_ONLY = frozenset({"check.publish", "gate.notify", "pr.close"})


def _plan_effect_outcomes() -> dict[str, set[str]]:
    """PLAN 7.2's effect row: ``pr.merge`` adds ``conflict`` and ``stale``, and so on."""
    row = next(line for line in PLAN.splitlines() if line.startswith("| `effect` |"))
    out: dict[str, set[str]] = {}
    for name, words in re.findall(r"`([a-z_.]+)` adds ((?:`[a-z_]+`(?: and |, )?)+)", row):
        out[name] = set(re.findall(r"`([a-z_]+)`", words))
    return out


def test_every_stale_edge_type_is_a_catalog_effect() -> None:
    assert set(MANIFEST.effects) >= STALE_EDGE_TYPES


def test_stale_edge_types_are_exactly_the_effects_with_a_stale_outcome() -> None:
    from_catalog = {n for n, spec in MANIFEST.effects.items() if "stale" in spec.outcomes}
    assert from_catalog == STALE_EDGE_TYPES


def test_stale_edge_types_agree_with_plan() -> None:
    planned = {n for n, outcomes in _plan_effect_outcomes().items() if "stale" in outcomes}
    assert planned, "the PLAN.md effect row was not found"
    assert planned == STALE_EDGE_TYPES


def test_every_implicit_type_is_a_catalog_effect_or_a_named_engine_only_effect() -> None:
    unknown = IMPLICIT_TYPES - set(MANIFEST.effects) - ENGINE_ONLY
    assert not unknown, f"not in the catalog and not a known engine-only effect: {sorted(unknown)}"


def test_engine_only_effects_are_not_nameable_in_a_workflow() -> None:
    assert not ENGINE_ONLY & set(MANIFEST.effects)
    assert not ENGINE_ONLY & set(get_args(Effect))
    assert ENGINE_ONLY <= IMPLICIT_TYPES


def test_a_catalog_effect_that_is_implicit_is_scoped() -> None:
    for name in IMPLICIT_TYPES & set(MANIFEST.effects):
        assert MANIFEST.effects[name].effect_class == "scoped", name


def test_no_gated_or_exposing_effect_is_implicit() -> None:
    # PLAN 6.3: only scoped effects are engine-implicit
    for name, spec in MANIFEST.effects.items():
        if spec.effect_class in ("gated", "exposing"):
            assert name not in IMPLICIT_TYPES, name


def test_implicit_types_agree_with_plan() -> None:
    row = next(line for line in PLAN.splitlines() if line.startswith("| `scoped` |"))
    implicit_text = row.split("**Engine-implicit")[1]
    assert "check runs" in implicit_text
    assert "gate notifications" in implicit_text
    assert "`pr.close`" in implicit_text
    assert "revert PR" in implicit_text
    assert ENGINE_ONLY | {"pr.open_revert"} == IMPLICIT_TYPES


def test_the_declared_scoped_effects_in_plan_are_catalog_effects_and_not_implicit_only() -> None:
    row = next(line for line in PLAN.splitlines() if line.startswith("| `scoped` |"))
    declared_text = row.split("**Declared:**")[1].split("**Engine-implicit")[0]
    for name in re.findall(r"`([a-z_.]+)`", declared_text):
        assert name in MANIFEST.effects, name
        assert MANIFEST.effects[name].effect_class == "scoped", name
