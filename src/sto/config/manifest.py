"""The agent profile manifest and the effect catalog (D2-18), loaded from ``catalog/``.

Both are data. The structural validator reads them: V2 for the outcomes of an agent or an
effect, V9 for a profile's tools and default tier. ``EFFECT_OUTCOMES`` in ``schema.py`` is the
schema layer's copy of the effect outcomes, and ``check_effect_outcomes_in_sync`` keeps the two
equal.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from sto.config.schema import EFFECT_OUTCOMES, ModelTier

CATALOG_DIR = Path(__file__).resolve().parents[3] / "catalog"

_IDENT = r"[a-z][a-z0-9_]*"
Ident = Annotated[str, StringConstraints(pattern=rf"^{_IDENT}$")]
Tool = Annotated[str, StringConstraints(pattern=rf"^{_IDENT}(\.({_IDENT}|\*))*$")]
Dotted = Annotated[str, StringConstraints(pattern=rf"^{_IDENT}(\.{_IDENT})*$")]
_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class ManifestError(ValueError):
    """The catalog is malformed, or the code and the catalog disagree."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Profile(_Model):
    role: Literal["orchestrator", "worker"]
    default_tier: ModelTier
    tools: frozenset[Tool]
    # An orchestrator declares the outcomes of its stage; a worker names its orchestrator.
    outcomes: frozenset[Ident] = frozenset()
    orchestrator: Ident | None = None

    @model_validator(mode="after")
    def _role_fields(self) -> Profile:
        if self.role == "orchestrator" and (not self.outcomes or self.orchestrator):
            raise ValueError("an orchestrator declares outcomes and no orchestrator")
        if self.role == "worker" and (self.outcomes or not self.orchestrator):
            raise ValueError("a worker names its orchestrator and declares no outcomes")
        return self


class WithKey(_Model):
    type: Literal["enum", "ident", "text"]
    required: bool = False
    values: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _values_only_for_enum(self) -> WithKey:
        if (self.type == "enum") != bool(self.values):
            raise ValueError("values are required for an enum and allowed for nothing else")
        return self


class EffectSpec(_Model):
    effect_class: Literal["internal", "scoped", "gated", "exposing"] = Field(alias="class")
    outcomes: frozenset[Ident]
    key_scope: tuple[Ident, ...] = Field(min_length=1)
    with_keys: Mapping[Ident, WithKey] = Field(alias="with")
    hold: str
    hold_default_seconds: int = 0

    @model_validator(mode="before")
    @classmethod
    def _parse_hold(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("hold"), str):
            m = _DURATION.match(data["hold"])
            if not m:
                raise ValueError("hold must be a duration such as 0s or 10m")
            data = {**data, "hold_default_seconds": int(m[1]) * _UNITS[m[2]]}
        return data

    @model_validator(mode="after")
    def _rules(self) -> EffectSpec:
        if "done" not in self.outcomes:
            raise ValueError("every effect has a done outcome")
        if self.hold_default_seconds and self.effect_class != "gated":
            raise ValueError("only a gated effect has a hold")
        return self


class Manifest(_Model):
    profiles: Mapping[Ident, Profile]
    effects: Mapping[Dotted, EffectSpec]

    def agent_outcomes(self, name: str) -> frozenset[str]:
        """Outcomes an agent stage may produce (V2). ``KeyError`` for an unknown profile."""
        profile = self.profiles[name]
        if profile.role != "orchestrator":
            raise KeyError(f"{name} is a worker and does not run a stage")
        return profile.outcomes

    def tools(self, name: str) -> frozenset[str]:
        """The tool allowlist of a profile (V9)."""
        return self.profiles[name].tools

    def default_tier(self, name: str) -> ModelTier:
        return self.profiles[name].default_tier

    def effect_outcomes(self, effect: str) -> frozenset[str]:
        return self.effects[effect].outcomes


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique(loader: _UniqueKeyLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node)
        if key in seen:
            raise ManifestError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return loader.construct_mapping(node)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique)


def _load(text: str, top: str) -> dict[str, Any]:
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506  (SafeLoader subclass)
    except yaml.YAMLError as exc:
        raise ManifestError(f"{top}: not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {top}:
        raise ManifestError(f"the document must be a map with the single key {top!r}")
    body = doc[top]
    if not isinstance(body, dict):
        raise ManifestError(f"{top} must be a map")
    return body


def parse_manifest(profiles_yaml: str, effects_yaml: str) -> Manifest:
    profiles = _load(profiles_yaml, "profiles")
    effects = _load(effects_yaml, "effects")
    try:
        manifest = Manifest.model_validate({"profiles": profiles, "effects": effects})
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise ManifestError(f"{where}: {first['msg']}") from exc
    for name, profile in manifest.profiles.items():
        if profile.role == "worker":
            boss = profile.orchestrator
            if boss != "review_panel":
                parent = manifest.profiles.get(boss or "")
                if parent is None or parent.role != "orchestrator":
                    raise ManifestError(f"{name}: orchestrator {boss!r} is not an orchestrator")
                if not profile.tools <= parent.tools:
                    extra = sorted(profile.tools - parent.tools)
                    raise ManifestError(f"{name}: tools {extra} are not in {boss}'s allowlist")
    frozen = Manifest.model_construct(
        profiles=MappingProxyType(dict(manifest.profiles)),
        effects=MappingProxyType(dict(manifest.effects)),
    )
    return frozen


def load_manifest(directory: Path | None = None) -> Manifest:
    root = directory or CATALOG_DIR
    return parse_manifest(
        (root / "profiles.yaml").read_text(encoding="utf-8"),
        (root / "effects.yaml").read_text(encoding="utf-8"),
    )


def check_effect_outcomes_in_sync(
    manifest: Manifest, table: Mapping[str, frozenset[str]] | None = None
) -> None:
    """Raise unless ``EFFECT_OUTCOMES`` agrees with the catalog.

    An effect missing from the table means only ``done``, so the catalog must say the same.
    """
    table = EFFECT_OUTCOMES if table is None else table
    problems = [
        f"{name}: not in the effect catalog" for name in table if name not in manifest.effects
    ]
    for name, spec in manifest.effects.items():
        have = table.get(name, frozenset({"done"}))
        if have != spec.outcomes:
            problems.append(
                f"{name}: schema has {sorted(have)}, catalog has {sorted(spec.outcomes)}"
            )
    if problems:
        raise ManifestError(
            "EFFECT_OUTCOMES and catalog/effects.yaml differ: " + "; ".join(problems)
        )
