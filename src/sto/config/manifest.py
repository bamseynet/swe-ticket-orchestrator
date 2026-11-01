"""The agent profile manifest and the effect catalog (D2-18), loaded from ``sto.catalog``.

Both are data. The structural validator reads them: V2 for the outcomes of an agent or an
effect, V9 for a profile's tools and default tier. ``EFFECT_OUTCOMES`` in ``schema.py`` is the
schema layer's copy of the effect outcomes, and ``check_effect_outcomes_in_sync`` keeps the two
equal. A loaded ``Manifest`` is read-only and dumps to stable JSON for the manifest digest.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from importlib import resources
from types import MappingProxyType
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from sto.config.schema import EFFECT_OUTCOMES, ModelTier

PROFILES_FILE = "profiles.yaml"
EFFECTS_FILE = "effects.yaml"

_IDENT = r"[a-z][a-z0-9_]*"
Ident = Annotated[str, StringConstraints(pattern=rf"^{_IDENT}$")]
Tool = Annotated[str, StringConstraints(pattern=rf"^{_IDENT}(\.({_IDENT}|\*))*$")]
Dotted = Annotated[str, StringConstraints(pattern=rf"^{_IDENT}(\.{_IDENT})*$")]
_DURATION = re.compile(r"([0-9]+)([smhd])")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# Wildcards are for a tool family the platform means to open whole. A ``*`` elsewhere is refused.
WILDCARD_TOOLS = frozenset({"browser.*"})
# PLAN 8.3, llm_review row: a review_panel worker holds a subset of these (a team may narrow it)
# and no other tool.
PANEL_TOOLS = frozenset(
    {"repo.read_file", "repo.search", "pr.diff", "checks.read", "record_finding"}
)
PANEL = "review_panel"  # a stage kind, not a profile: the orchestrator a panel worker names
# PLAN 6.3 gives exactly three shapes. ``effect_key()`` adds the effect type to each.
KEY_SCOPES = frozenset(
    {
        ("run", "stage", "visit", "subject"),
        ("run", "branch"),  # pr.ensure_draft: finds or creates, one PR per branch
        ("run", "merge_sha"),  # pr.open_revert: a declared and an implicit revert open one PR
    }
)


class ManifestError(ValueError):
    """The catalog is malformed, or the code and the catalog disagree."""

    def __init__(self, problems: list[str] | str) -> None:
        self.problems = [problems] if isinstance(problems, str) else list(problems)
        super().__init__("\n".join(self.problems))


def _no_repeats(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        seen: set[Any] = set()
        for item in value:
            try:
                duplicate = item in seen
            except TypeError:
                raise ValueError("items must be plain words, not lists or maps") from None
            if duplicate:
                raise ValueError(f"{item!r} is listed twice")
            seen.add(item)
    return value


def _check_tools(tools: frozenset[str]) -> frozenset[str]:
    for tool in tools:
        if "*" in tool and tool not in WILDCARD_TOOLS:
            raise ValueError(
                f"wildcard {tool!r} is not allowed; wildcards: {sorted(WILDCARD_TOOLS)}"
            )
    return tools


def _check_scope(parts: tuple[str, ...]) -> tuple[str, ...]:
    if parts not in KEY_SCOPES:
        shapes = "; ".join("[" + ", ".join(k) + "]" for k in sorted(KEY_SCOPES))
        raise ValueError(f"key_scope {list(parts)} is not one of: {shapes}")
    return parts


def _to_set(value: Any) -> Any:
    return frozenset(value) if isinstance(value, list) else value


def _sorted_list(value: frozenset[str]) -> list[str]:
    return sorted(value)


def _freeze_map[K, V](value: Mapping[K, V]) -> Mapping[K, V]:
    return MappingProxyType(dict(value))


def _dump_map[K, V](value: Mapping[K, V]) -> dict[K, V]:
    return dict(sorted(value.items(), key=lambda kv: str(kv[0])))


Names = Annotated[
    frozenset[Ident],
    BeforeValidator(_to_set),
    BeforeValidator(_no_repeats),
    PlainSerializer(_sorted_list, return_type=list[str]),
]
ToolSet = Annotated[
    frozenset[Tool],
    BeforeValidator(_to_set),
    BeforeValidator(_no_repeats),
    AfterValidator(_check_tools),
    PlainSerializer(_sorted_list, return_type=list[str]),
]
KeyScope = Annotated[
    tuple[Ident, ...],
    BeforeValidator(_no_repeats),
    BeforeValidator(lambda v: tuple(v) if isinstance(v, list) else v),
    AfterValidator(_check_scope),
]
type ReadOnlyMap[K, V] = Annotated[
    Mapping[K, V], AfterValidator(_freeze_map), PlainSerializer(_dump_map)
]


def _seconds(value: Any) -> Any:
    if not isinstance(value, str):
        raise ValueError("hold must be a duration such as 0s or 10m")
    m = _DURATION.fullmatch(value)
    if not m:
        raise ValueError("hold must be a duration such as 0s or 10m")
    return int(m[1]) * _UNITS[m[2]]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Profile(_Model):
    role: Literal["orchestrator", "worker"]
    default_tier: ModelTier
    tools: ToolSet
    # An orchestrator declares the outcomes of its stage; a worker names its orchestrator.
    outcomes: Names = frozenset()
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

    @model_validator(mode="before")
    @classmethod
    def _tuple(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("values"), list):
            _no_repeats(data["values"])
            return {**data, "values": tuple(data["values"])}
        return data

    @model_validator(mode="after")
    def _values_only_for_enum(self) -> WithKey:
        if (self.type == "enum") != bool(self.values):
            raise ValueError("values are required for an enum and allowed for nothing else")
        return self


class EffectSpec(_Model):
    effect_class: Literal["internal", "scoped", "gated", "exposing"] = Field(alias="class")
    outcomes: Names
    key_scope: KeyScope
    with_keys: ReadOnlyMap[Ident, WithKey] = Field(alias="with")
    hold_seconds: Annotated[int, BeforeValidator(_seconds)] = Field(alias="hold")

    @model_validator(mode="after")
    def _rules(self) -> EffectSpec:
        if "done" not in self.outcomes:
            raise ValueError("every effect has a done outcome")
        if self.hold_seconds and self.effect_class != "gated":
            raise ValueError("only a gated effect has a hold")
        return self


class Manifest(_Model):
    profiles: ReadOnlyMap[Ident, Profile]
    effects: ReadOnlyMap[Dotted, EffectSpec]

    def agent_outcomes(self, name: str) -> frozenset[str]:
        """Outcomes an agent stage may produce (V2). ``KeyError`` for a worker or unknown name."""
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
        """Outcomes an effect stage must have edges for (V2). ``KeyError`` if not in the catalog."""
        return self.effects[effect].outcomes


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate and non-scalar keys."""


def _construct_unique(loader: _UniqueKeyLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        line = key_node.start_mark.line + 1
        try:
            key = loader.construct_object(key_node)
            duplicate = key in seen
            seen.add(key)
        except TypeError as exc:
            raise ManifestError(
                f"line {line}: a key must be a plain word, not a list or map"
            ) from exc
        if duplicate:
            raise ManifestError(f"line {line}: duplicate key {key!r}")
    return loader.construct_mapping(node)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique)


def _load(text: str, file: str, top: str) -> dict[str, Any]:
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506  (SafeLoader subclass)
    except ManifestError as exc:
        raise ManifestError([f"{file}: {p}" for p in exc.problems]) from exc
    except yaml.YAMLError as exc:
        raise ManifestError(f"{file}: not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {top} or not isinstance(doc[top], dict):
        raise ManifestError(f"{file}: the document must be a map with the single key {top!r}")
    body: dict[str, Any] = doc[top]
    return body


def _problems(file: str, exc: ValidationError) -> list[str]:
    return [f"{file}: {'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]


def _cross_checks(profiles: Mapping[str, Profile], file: str) -> list[str]:
    out: list[str] = []
    if PANEL in profiles:
        out.append(f"{file}: {PANEL} is a stage kind and cannot be a profile name")
    for name, p in profiles.items():
        if p.role != "worker":
            continue
        if p.orchestrator == PANEL:
            extra = sorted(p.tools - PANEL_TOOLS)
            if extra:
                out.append(f"{file}: {name}: a panel worker may not hold {extra}")
            if "record_finding" not in p.tools:
                out.append(f"{file}: {name}: a panel worker must hold record_finding")
            continue
        parent = profiles.get(p.orchestrator or "")
        if parent is None or parent.role != "orchestrator":
            out.append(f"{file}: {name}: orchestrator {p.orchestrator!r} is not an orchestrator")
        elif not p.tools <= parent.tools:
            out.append(
                f"{file}: {name}: tools {sorted(p.tools - parent.tools)} "
                f"are not in {p.orchestrator}'s allowlist"
            )
    return out


def parse_manifest(
    profiles_yaml: str,
    effects_yaml: str,
    *,
    profiles_file: str = PROFILES_FILE,
    effects_file: str = EFFECTS_FILE,
) -> Manifest:
    """Parse both documents. Every problem found is reported, each naming its file."""
    problems: list[str] = []
    parsed: dict[str, Any] = {}
    for text, file, top, model in (
        (profiles_yaml, profiles_file, "profiles", Profile),
        (effects_yaml, effects_file, "effects", EffectSpec),
    ):
        try:
            body = _load(text, file, top)
        except ManifestError as exc:
            problems += exc.problems
            continue
        adapter: TypeAdapter[Any] = TypeAdapter(dict[str, model])  # type: ignore[valid-type]
        try:
            parsed[top] = adapter.validate_python(body)
        except ValidationError as exc:
            problems += _problems(file, exc)
    if not problems:
        try:
            manifest = Manifest(profiles=parsed["profiles"], effects=parsed["effects"])
        except ValidationError as exc:  # key names are checked here
            raise ManifestError(_problems(f"{profiles_file}/{effects_file}", exc)) from exc
        problems = _cross_checks(manifest.profiles, profiles_file)
        if not problems:
            return manifest
    raise ManifestError(problems)


def load_manifest() -> Manifest:
    """Load the catalog that ships inside the package."""
    root = resources.files("sto.catalog")
    return parse_manifest(
        root.joinpath(PROFILES_FILE).read_text(encoding="utf-8"),
        root.joinpath(EFFECTS_FILE).read_text(encoding="utf-8"),
    )


def check_effect_outcomes_in_sync(
    manifest: Manifest, table: Mapping[str, frozenset[str]] | None = None
) -> None:
    """Raise unless ``EFFECT_OUTCOMES`` agrees with the catalog.

    An effect missing from the table means only ``done``, so the catalog must say the same.
    """
    table = EFFECT_OUTCOMES if table is None else table
    problems = [
        f"{n}: not in the effect catalog" for n in sorted(table) if n not in manifest.effects
    ]
    for name, spec in manifest.effects.items():
        have = table.get(name, frozenset({"done"}))
        if have != spec.outcomes:
            problems.append(
                f"{name}: schema has {sorted(have)}, catalog has {sorted(spec.outcomes)}"
            )
    if problems:
        raise ManifestError(["EFFECT_OUTCOMES and effects.yaml differ: " + "; ".join(problems)])
