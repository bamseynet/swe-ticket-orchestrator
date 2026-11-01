"""Typed models for every configuration document in PLAN section 7.2, and their JSON Schema (D2-01).

Four documents: ``Workflow``, ``WorkflowOverlay``, ``TeamConfig`` and ``OrgPolicy``. This module is
the syntax and field-value layer only. The semantic rules V1 to V17 are later issues and build on
these models.

Every model refuses unknown keys, is strict about types (a ``"120"`` is not ``120``) and is deeply
immutable: sequences are tuples and mappings are read-only. There is deliberately no
``auto_approve`` key anywhere, so the refusal of unknown keys is what keeps a timeout from
approving. In a full document ``null`` is refused: it removes a key only in a ``WorkflowOverlay``,
where JSON Merge Patch (RFC 7386) gives it that meaning, so a gate cannot be dropped by writing
``null`` where a required value belongs. Overlay models dump with ``exclude_unset`` by default so a
dump never turns an unset field into the removing ``null``; use ``to_patch()``.

``load_document`` is the only YAML entry point and every refusal is a ``SchemaError`` with the line
of the offending key. It reads a strict subset of YAML: PyYAML reads a bare ``on`` as boolean true,
which is why the edge key is ``next``, so the loader refuses duplicate keys, aliases, merge keys,
non-string keys, tags beyond the core JSON ones, nesting over ``MAX_DEPTH``, and YAML 1.1 number
forms (``0x10``, ``010``, ``1:00``, ``1_0``): only plain decimal integers and floats are numbers.
Dates must be ``YYYY-MM-DD``; instants must carry a UTC offset.

The JSON Schemas in ``schemas/`` are editor hints and are looser than the loader (they cannot say
that a date is real, that a ref is valid, or which outcomes a given effect has). A document that
validates in an editor is not thereby loadable; ``load_document`` is the authority.

``python -m sto.config.schema --write`` regenerates ``schemas/*.schema.json``; ``--check`` fails if
they are stale (a test runs the same comparison).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
import sys
import unicodedata
import zoneinfo
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar, get_args, get_origin

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    ValidationError,
    ValidationInfo,
    WrapSerializer,
    create_model,
    field_validator,
    model_validator,
)

API_VERSION = "sto/v1"
PLATFORM_MAX_STEPS = 500
PLATFORM_MAX_RUN_AGE_DAYS = 300
MAX_DEPTH = 64  # nesting of collections in a document; also bounds ``with``
MAX_ISSUES = 50  # more than this are summarised, so a hostile file cannot make a huge message
_MAX_TEXT = 300  # longest user-supplied text echoed into an error

# --- immutable containers --------------------------------------------------------------------


def _seq(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


class FrozenMap[K, V](Mapping[K, V]):
    """A read-only mapping that pickles and deep-copies, unlike ``types.MappingProxyType``.

    It has no mutators, so item assignment raises ``TypeError`` and ``pop``/``clear`` raise
    ``AttributeError``. It compares equal to a ``dict`` with the same items. It is deliberately
    not hashable (a mapping that compares equal to a dict must not be), so a frozen model that
    holds one cannot be hashed either.

    To get plain data out, use ``model_dump`` (``mode="json"`` for JSON types): it turns every
    ``FrozenMap`` into a ``dict``. A bare ``FrozenMap`` is not accepted by ``json.dumps``,
    ``pydantic_core.to_jsonable_python`` or ``yaml.safe_dump``.
    """

    __slots__ = ("_data",)
    _data: dict[K, V]

    def __init__(self, data: Mapping[K, V] | None = None) -> None:
        object.__setattr__(self, "_data", dict(data or {}))

    def __getitem__(self, key: K) -> V:
        return self._data[key]

    def __iter__(self) -> Iterator[K]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"FrozenMap({self._data!r})"

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("FrozenMap is read-only")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("FrozenMap is read-only")

    def __reduce__(self) -> tuple[Any, ...]:
        return (FrozenMap, (dict(self._data),))

    __hash__ = None  # type: ignore[assignment]


def _freeze_map(value: Mapping[Any, Any]) -> Mapping[Any, Any]:
    return FrozenMap(value)


def _thaw_map(value: Mapping[Any, Any], handler: Any) -> Any:
    return handler(dict(value))  # a read-only view has no serializer of its own


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw_json(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw_json(v) for v in value]
    return value


_T_ = TypeVar("_T_")
_K_ = TypeVar("_K_")
_V_ = TypeVar("_V_")
# Old-style generic aliases, not ``type`` statements: those add a named $ref to the JSON Schema.
Seq = Annotated[tuple[_T_, ...], BeforeValidator(_seq)]
FMap = Annotated[Mapping[_K_, _V_], AfterValidator(_freeze_map), WrapSerializer(_thaw_map)]


def _encodable(value: str) -> str:
    """Refuse a string with a lone surrogate: it loads, but nothing can serialise it."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("contains a lone surrogate, which is not valid Unicode text") from None
    return value


def _json_only(value: Any, depth: int = 0) -> Any:
    """Freeze a ``with`` value, allowing only what JSON can hold."""
    if depth > MAX_DEPTH:
        raise ValueError(f"nesting deeper than {MAX_DEPTH} levels")
    if isinstance(value, str):
        return _encodable(value)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("infinity and NaN are not JSON values")
        return value
    if isinstance(value, list | tuple):
        return tuple(_json_only(v, depth + 1) for v in value)
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("keys must be strings")
        return FrozenMap({_encodable(k): _json_only(v, depth + 1) for k, v in value.items()})
    raise ValueError(
        f"a {type(value).__name__} is not a JSON value; use strings, numbers and lists"
    )


def _with_map(value: Mapping[str, Any]) -> Mapping[str, Any]:
    frozen = _json_only(value)
    assert isinstance(frozen, Mapping)
    return frozen


# --- shared vocabulary -----------------------------------------------------------------------

Ident = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]


def _one_line(value: str) -> str:
    _encodable(value)
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise ValueError("control characters (including newlines and tabs) are not allowed here")
    return value


def _paragraph(value: str) -> str:
    _encodable(value)
    if any(unicodedata.category(c) == "Cc" and c not in "\n\t" for c in value):
        raise ValueError("control characters other than newline and tab are not allowed here")
    return value


Text = Annotated[str, StringConstraints(min_length=1, pattern=r"\S"), AfterValidator(_one_line)]
LongText = Annotated[
    str, StringConstraints(min_length=1, pattern=r"\S"), AfterValidator(_paragraph)
]
Duration = Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]*[smhdw]$")]
OutcomeKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]+$")]
TeamName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_-]*$")]
Idents = Annotated[Seq[Ident], Field(min_length=1)]
Texts = Annotated[Seq[Text], Field(min_length=1)]
Money = Annotated[float, Field(gt=0, allow_inf_nan=False)]

Role = Ident
ModelTier = Literal["fast", "standard", "deep"]
Severity = Literal["low", "medium", "high", "critical"]
SEVERITIES = get_args(Severity)
GateType = Literal["review", "qa", "custom", "pre_push"]
Decision = Literal["approve", "request_changes", "reject", "retest", "waive"]
Surface = Literal["ui", "slack", "github"]
CarryOver = Literal["patch_id", "none"]
Weekday = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
Effect = Literal[
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
RouteField = Literal["risk", "issue_type", "priority", "component", "label", "repo_ci_trust"]
TerminalResult = Literal["done", "rejected", "closed", "expired", "done_with_incident"]
STAGE_KINDS = ("agent", "review_panel", "checks", "gate", "effect", "wait", "route", "terminal")

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def duration_seconds(value: str) -> int:
    """Seconds in a ``Duration`` such as ``90m`` or ``2w``."""
    if not re.fullmatch(r"[1-9][0-9]*[smhdw]", value):
        raise ValueError(f"{value!r} is not a duration; use a number and one of s, m, h, d, w")
    return int(value[:-1]) * _DURATION_UNITS[value[-1]]


def _run_age(value: str) -> str:
    if duration_seconds(value) > PLATFORM_MAX_RUN_AGE_DAYS * 86400:
        raise ValueError(f"{value} exceeds the platform maximum of {PLATFORM_MAX_RUN_AGE_DAYS}d")
    return value


def _date(value: Any) -> Any:
    if isinstance(value, dt.datetime):
        raise ValueError("expected a date written YYYY-MM-DD, not a date and time")
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            raise ValueError(f"{value} is not a real date") from None
    raise ValueError("expected a date written YYYY-MM-DD")


def _instant(value: Any) -> Any:
    if isinstance(value, str):
        try:
            value = dt.datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("expected a date and time such as 2026-12-24T00:00:00Z") from None
    if not isinstance(value, dt.datetime):
        raise ValueError("expected a date and time such as 2026-12-24T00:00:00Z")
    offset = value.utcoffset()
    if offset is None:
        raise ValueError(
            "a date and time here must carry a UTC offset (Z or +01:00); a bare one is ambiguous"
        )
    if offset % dt.timedelta(minutes=1):
        raise ValueError("the UTC offset must be a whole number of minutes, such as +05:30")
    return value


_NOT_REAL_ZONES = frozenset({"localtime", "posixrules", "Factory"})


def _timezone(value: str) -> str:
    try:
        if value in _NOT_REAL_ZONES:
            raise ValueError(value)  # present in many tz databases, but not places
        zoneinfo.ZoneInfo(value)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):  # OSError: "Europe" is a folder
        raise ValueError("unknown timezone; use an IANA name such as Europe/London") from None
    return value


def _hours(value: str) -> str:
    m = re.fullmatch(r"([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])", value)
    if not m:
        raise ValueError("hours must be HH:MM-HH:MM on a 24-hour clock, for example 09:00-17:30")
    if (m[1], m[2]) >= (m[3], m[4]):
        raise ValueError("hours must end after they start; split a night shift across two days")
    return value


def _git_ref(value: str) -> str:
    parts = value.split("/")
    if (
        ".." in value
        or "//" in value
        or value.endswith(("/", "."))
        or any(p.startswith(".") or p.endswith(".lock") for p in parts)
    ):
        raise ValueError("not a valid branch name")
    return value


Date = Annotated[dt.date, BeforeValidator(_date)]
Instant = Annotated[dt.datetime, BeforeValidator(_instant)]
RunAge = Annotated[Duration, AfterValidator(_run_age)]
Timezone = Annotated[Text, AfterValidator(_timezone)]
Hours = Annotated[str, AfterValidator(_hours)]
RepoName = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*$")
]
BranchName = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$"), AfterValidator(_git_ref)
]

# Outcomes a kind can produce. An agent's come from its profile and a route's from its field
# values, so those two are open. ``expired`` and ``retest`` are legal only when the gate allows
# them; whether an edge is required for each is V2. A gate has no ``timeout`` outcome: a timeout
# never approves, and escalation or expiry are the only things a timeout can do.
GATE_OUTCOMES = frozenset({"approved", "changes_requested", "rejected", "retest", "expired"})
OUTCOMES_BY_KIND: dict[str, frozenset[str] | None] = {
    "agent": None,
    "review_panel": frozenset({"clean", "findings", "degraded"}),
    "checks": frozenset({"green", "red"}),
    "gate": GATE_OUTCOMES,
    "effect": frozenset({"done", "conflict", "stale"}),
    "wait": frozenset({"resumed", "timeout"}),
    "route": None,
}
EFFECT_OUTCOMES: dict[str, frozenset[str]] = {
    "pr.merge": frozenset({"done", "conflict", "stale"}),
    "pr.update_branch": frozenset({"done", "conflict"}),
    "release.trigger": frozenset({"done", "stale"}),
}

_NULL_HELP = (
    "null is not allowed here: omit the key. "
    "null removes a key only among the patch fields of a WorkflowOverlay"
)


class _Strict(BaseModel):
    """Full documents: strict, frozen, unknown keys refused, and no nulls."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, populate_by_name=False)

    @model_validator(mode="before")
    @classmethod
    def _no_nulls(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key, value in data.items():
                if value is None:
                    raise ValueError(f"{key}: {_NULL_HELP}")
        return data


class _Patch(BaseModel):
    """Overlay fragments: every field optional, ``null`` means remove.

    ``model_dump`` leaves out fields that were not set, because an unset field dumped as ``None``
    would read back as a removal. Pass ``exclude_unset=False`` explicitly to get the other kind.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, populate_by_name=False)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("exclude_unset", True)
        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("exclude_unset", True)
        return super().model_dump_json(**kwargs)


_PATCHES: dict[str, type[_Patch]] = {}


def _patchable(ann: Any) -> Any:
    if isinstance(ann, type) and issubclass(ann, BaseModel):
        return _patch_of(ann, ann.__name__ + "Patch")
    if get_origin(ann) is Mapping:  # a map merges key by key, and null removes a key
        key, val = get_args(ann)
        return Mapping[key, val | None]  # type: ignore[valid-type]
    args = get_args(ann)
    if args and type(None) in args:
        inner = [_patchable(a) for a in args if a is not type(None)]
        if len(inner) == 1 and inner[0] is not args[0]:
            return inner[0] | None
    return ann


def _patch_of(model: type[BaseModel], name: str) -> type[_Patch]:
    """The JSON Merge Patch shape of ``model``: every field optional, nested models too."""
    if name not in _PATCHES:
        fields: dict[str, Any] = {}
        for fname, info in model.model_fields.items():
            ann = _patchable(info.annotation)
            inner: Any = Any if ann is None else ann
            if info.metadata:  # constraints and validators live here, not in ``annotation``
                # They apply to the value, not to the ``None`` that means "remove".
                inner = Annotated.__class_getitem__((inner, *info.metadata))  # type: ignore[attr-defined]
            optional: Any = inner | None
            fields[fname] = (optional, Field(default=None, alias=info.alias))
        globals()[name] = _PATCHES[name] = create_model(
            name, __base__=_Patch, __module__=__name__, **fields
        )
    return _PATCHES[name]


# --- workflow --------------------------------------------------------------------------------


class Metadata(_Strict):
    name: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]*$")]
    team: TeamName


class Sprint(_Strict):
    mode: Literal["any", "active_only"]


class Intake(_Strict):
    source: Literal["github", "jira", "linear", "azure_devops"]
    project: Text
    label: Text
    issue_types: Texts | None = None
    extra_filter: Text | None = None
    sprint: Sprint | None = None


class Repo(_Strict):
    name: RepoName
    base: BranchName
    sandbox_image: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]*$")]


class Limits(_Strict):
    loops: FMap[Ident, Annotated[int, Field(ge=1)]] = Field(default_factory=lambda: FrozenMap())
    max_steps_per_run: Annotated[int, Field(ge=1, le=PLATFORM_MAX_STEPS)]
    max_run_age: RunAge


class DefinitionOfDone(_Strict):
    stage: Ident
    check: Literal["ac_present", "checks_green", "coverage_at_least", "no_findings_above"]
    value: int | float | str | None = None

    @model_validator(mode="after")
    def _value_matches_the_check(self) -> DefinitionOfDone:
        v = self.value
        if self.check == "coverage_at_least":
            if (
                isinstance(v, bool)
                or not isinstance(v, int | float)
                or not 0 <= v <= 100  # first: a 400-digit int would overflow isfinite
                or not math.isfinite(v)
            ):
                raise ValueError("coverage_at_least needs a number from 0 to 100 as `value`")
        elif self.check == "no_findings_above":
            if v not in SEVERITIES:
                raise ValueError(f"no_findings_above needs `value` to be one of {SEVERITIES}")
        elif v is not None:
            raise ValueError(f"{self.check} takes no `value`")
        return self


class Edge(_Strict):
    to: Ident
    loop: Ident | None = None


Next = Annotated[FMap[OutcomeKey, Ident | Edge], Field(min_length=1)]


class Quorum(_Strict):
    role: Role
    count: Annotated[int, Field(ge=1)]


class ApproverOf(_Strict):
    approver_of: Ident


class SeparationOfDuties(_Strict):
    not_: Annotated[
        Seq[Literal["author", "requester", "committer"] | ApproverOf], Field(min_length=1)
    ] = Field(alias="not")


class Timeouts(_Strict):
    remind_after: Duration | None = None
    escalate_after: Duration | None = None
    escalate_to: Role | None = None
    expire_after: Duration | None = None


class Gate(_Strict):
    type: GateType
    eligible_roles: Idents  # the only authority on who may decide; never empty (V7)
    decisions: Annotated[Seq[Decision], Field(min_length=1)]
    decision_surfaces: Annotated[Seq[Surface], Field(min_length=1)]
    quorum: Annotated[Seq[Quorum], Field(min_length=1)] | None = None
    path_owners: Literal["none", "codeowners"] | None = None
    separation_of_duties: SeparationOfDuties | None = None
    carry_over: CarryOver = "none"
    timeouts: Timeouts | None = None


class _StageBase(_Strict):
    kind: str

    @field_validator("next", check_fields=False)
    @classmethod
    def _outcomes_belong_to_the_kind(cls, v: Next, info: ValidationInfo) -> Next:
        kind = info.data.get("kind")
        allowed = OUTCOMES_BY_KIND.get(str(kind))
        extra = None if allowed is None else sorted(set(v) - allowed)
        if extra and allowed:
            raise ValueError(
                f"outcome {extra[0]!r} does not exist for a {kind} stage; "
                f"use one of: {', '.join(sorted(allowed))}"
            )
        return v


class AgentStage(_StageBase):
    kind: Literal["agent"]
    agent: Ident
    model_tier: ModelTier | None = None
    max_attempts: Annotated[int, Field(ge=1)] | None = None
    next: Next


class ReviewPanelStage(_StageBase):
    kind: Literal["review_panel"]
    reviewers: Idents
    required: Idents
    fail_closed: bool = False
    block_on: Severity
    next: Next


class ChecksStage(_StageBase):
    kind: Literal["checks"]
    source: Literal["ci", "qa_suite", "post_merge"]
    required: Texts | Literal["team_default"]
    timeout: Duration
    next: Next


class GateStage(_StageBase):
    kind: Literal["gate"]
    gate: Gate
    next: Next


class EffectStage(_StageBase):
    kind: Literal["effect"]
    effect: Effect
    with_: (
        Annotated[Mapping[str, Any], AfterValidator(_with_map), PlainSerializer(_thaw_json)] | None
    ) = Field(default=None, alias="with")
    requires_gates: Idents | None = None
    next: Next

    @field_validator("next")
    @classmethod
    def _outcomes_belong_to_the_effect(cls, v: Next, info: ValidationInfo) -> Next:
        effect = info.data.get("effect")
        if effect is None:
            return v
        allowed = EFFECT_OUTCOMES.get(effect, frozenset({"done"}))
        extra = sorted(set(v) - allowed)
        if extra:
            raise ValueError(
                f"outcome {extra[0]!r} does not exist for effect {effect}; "
                f"use one of: {', '.join(sorted(allowed))}"
            )
        return v


class WaitStage(_StageBase):
    kind: Literal["wait"]
    wait_for: Literal["human_answer", "environment_ready"]
    timeout: Duration
    next: Next


class RouteStage(_StageBase):
    kind: Literal["route"]
    field: RouteField
    order: Texts | None = None
    next: Next


class TerminalStage(_Strict):
    kind: Literal["terminal"]
    result: TerminalResult


Stage = Annotated[
    AgentStage
    | ReviewPanelStage
    | ChecksStage
    | GateStage
    | EffectStage
    | WaitStage
    | RouteStage
    | TerminalStage,
    Field(discriminator="kind"),
]


class Workflow(_Strict):
    apiVersion: Literal["sto/v1"]
    kind: Literal["Workflow"]
    metadata: Metadata
    intake: Intake | None = None  # a template leaves these to its overlays: see missing_for_publish
    repo: Repo | None = None
    limits: Limits
    on_external_commit: Ident | None = None
    definition_of_done: Seq[DefinitionOfDone] = ()
    start: Ident
    stages: Annotated[FMap[Ident, Stage], Field(min_length=1)]

    def missing_for_publish(self) -> list[str]:
        """Top-level keys a template may omit but a published, runnable workflow must have."""
        return [k for k in ("intake", "repo") if getattr(self, k) is None]


# --- overlay ---------------------------------------------------------------------------------

IntakePatch = _patch_of(Intake, "IntakePatch")
RepoPatch = _patch_of(Repo, "RepoPatch")
LimitsPatch = _patch_of(Limits, "LimitsPatch")
GatePatch = _patch_of(Gate, "GatePatch")


class StagePatch(_Patch):
    """A merge patch for one stage. The merged result is validated as a stage after flattening."""

    kind: (
        Literal["agent", "review_panel", "checks", "gate", "effect", "wait", "route", "terminal"]
        | None
    ) = None
    next: FMap[OutcomeKey, Ident | Edge | None] | None = None
    agent: Ident | None = None
    model_tier: ModelTier | None = None
    max_attempts: Annotated[int, Field(ge=1)] | None = None
    reviewers: Idents | None = None
    required: Idents | Texts | Literal["team_default"] | None = None
    fail_closed: bool | None = None
    block_on: Severity | None = None
    source: Literal["ci", "qa_suite", "post_merge"] | None = None
    timeout: Duration | None = None
    gate: GatePatch | None = None  # type: ignore[valid-type]
    effect: Effect | None = None
    with_: (
        Annotated[Mapping[str, Any], AfterValidator(_with_map), PlainSerializer(_thaw_json)] | None
    ) = Field(default=None, alias="with")
    requires_gates: Idents | None = None
    wait_for: Literal["human_answer", "environment_ready"] | None = None
    field: RouteField | None = None
    order: Texts | None = None
    result: TerminalResult | None = None


OVERLAY_HEAD_KEYS = ("apiVersion", "kind", "metadata", "extends")


class WorkflowOverlay(_Patch):
    apiVersion: Literal["sto/v1"]
    kind: Literal["WorkflowOverlay"]
    metadata: Metadata
    extends: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]+@[0-9][A-Za-z0-9.]*$")]
    intake: IntakePatch | None = None  # type: ignore[valid-type]
    repo: RepoPatch | None = None  # type: ignore[valid-type]
    limits: LimitsPatch | None = None  # type: ignore[valid-type]
    on_external_commit: Ident | None = None
    definition_of_done: Seq[DefinitionOfDone] | None = None
    start: Ident | None = None
    stages: FMap[Ident, StagePatch | None] | None = None

    def to_patch(self) -> dict[str, Any]:
        """Only the patch body, as plain JSON data with the keys as written in the document.

        ``apiVersion``, ``kind``, ``metadata`` and ``extends`` describe the overlay, not the
        change, and merging them into a workflow would overwrite its own ``kind``; they are left
        out. Fields that were not set are left out too, and an explicit ``null`` is kept because
        it means "remove". Do not pass the result through anything that drops ``None``.
        """
        body = self.model_dump(mode="json", by_alias=True)
        return {k: v for k, v in body.items() if k not in OVERLAY_HEAD_KEYS}


# --- team config -----------------------------------------------------------------------------


class Calendar(_Strict):
    timezone: Timezone
    workdays: Annotated[Seq[Weekday], Field(min_length=1)]
    hours: Hours
    holidays: Text | None = None

    @field_validator("workdays")
    @classmethod
    def _no_repeated_days(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(v)) != len(v):
            raise ValueError("a weekday is listed twice")
        return v


class TeamSprint(_Strict):
    cadence: Literal["1w", "2w", "3w", "4w"]
    anchor: Date
    merge_freeze_before_end: Duration | None = None


class QaConfig(_Strict):
    test_domains: Texts


class DenyWindow(_Strict):
    from_: Instant = Field(alias="from")
    to: Instant
    reason: Text

    @model_validator(mode="after")
    def _ends_after_it_starts(self) -> DenyWindow:
        if self.from_ >= self.to:
            raise ValueError("`to` must be after `from`")
        return self


class ChangeWindows(_Strict):
    deny: Seq[DenyWindow] = ()
    allow_only: Text | None = None


class Budgets(_Strict):
    run_usd: Money
    team_monthly_usd: Money
    stage_usd: FMap[Ident, Money] | None = None
    session_seconds_per_run: Annotated[int, Field(ge=1)] | None = None


class CustomProfile(_Strict):
    base: Ident
    prompt_addendum: LongText | None = None
    tools: Annotated[Seq[Text], Field(min_length=1)] | None = None


class TeamMetadata(_Strict):
    team: TeamName


class TeamConfig(_Strict):
    apiVersion: Literal["sto/v1"]
    kind: Literal["TeamConfig"]
    metadata: TeamMetadata
    calendar: Calendar | None = None
    sprint: TeamSprint | None = None
    wip_limit: Annotated[int, Field(ge=1)] | None = None
    qa: QaConfig | None = None
    change_windows: ChangeWindows | None = None
    budgets: Budgets  # "every run has a budget" (PLAN 7.5)
    custom_profiles: FMap[Ident, CustomProfile] | None = None


# --- org policy ------------------------------------------------------------------------------

MandatoryGateType = Literal["pre_push", "review", "qa"]
MANDATORY_GATES = frozenset(get_args(MandatoryGateType))


class Floors(_Strict):
    single_human_allowed: bool = False
    requester_excluded_from: Seq[GateType] = ("review", "pre_push")
    mandatory_gate_roles: FMap[MandatoryGateType, Idents]
    decision_surfaces: Annotated[
        FMap[GateType, Annotated[Seq[Surface], Field(min_length=1)]], Field(min_length=1)
    ]
    waive_allowed: bool = False
    hold_after_approval_min: Duration
    require_up_to_date: bool = True
    require_up_to_date_waived_for: Seq[Text] = ()
    identity_max_age: Duration
    public_repo_intake: bool = False
    ci_without_secrets_waived_for: Seq[Text] = ()
    route_to_gate_allowed: bool = False

    @field_validator("mandatory_gate_roles")
    @classmethod
    def _every_mandatory_gate_has_roles_and_never_developer(
        cls, v: Mapping[str, tuple[str, ...]]
    ) -> Mapping[str, tuple[str, ...]]:
        missing = sorted(MANDATORY_GATES - set(v))
        if missing:
            raise ValueError(f"name the roles for {', '.join(missing)}: none would mean anyone")
        for gate, roles in v.items():
            if "developer" in roles:
                raise ValueError(f"{gate}: a mandatory gate is never decided by developer")
        return v


class RequiredGateWhen(_Strict):
    field: RouteField
    value: Text


class RequiredGate(_Strict):
    id: Ident
    role: Role
    when: RequiredGateWhen | None = None


class TeamPolicy(_Strict):
    required_gates: Seq[RequiredGate] = ()
    min_quorum: FMap[GateType, Annotated[int, Field(ge=1)]] = Field(
        default_factory=lambda: FrozenMap()
    )
    allowed_carry_over: Annotated[Seq[CarryOver], Field(min_length=1)] | None = None


class OrgPolicy(_Strict):
    apiVersion: Literal["sto/v1"]
    kind: Literal["OrgPolicy"]
    floors: Floors
    teams: FMap[TeamName, TeamPolicy] = Field(default_factory=lambda: FrozenMap())


Document = Workflow | WorkflowOverlay | TeamConfig | OrgPolicy
_KINDS: dict[str, type[Document]] = {
    "Workflow": Workflow,
    "WorkflowOverlay": WorkflowOverlay,
    "TeamConfig": TeamConfig,
    "OrgPolicy": OrgPolicy,
}

# --- loading ---------------------------------------------------------------------------------


def _clean(text: str, limit: int = _MAX_TEXT) -> str:
    """Make user text safe to echo: control characters shown escaped, and bounded in length."""
    shown = "".join(c if c.isprintable() else c.encode("unicode_escape").decode() for c in text)
    return shown if len(shown) <= limit else shown[:limit] + "..."


@dataclass(frozen=True)
class Issue:
    line: int | None
    path: str
    message: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _clean(self.path))
        object.__setattr__(self, "message", _clean(self.message, 2 * _MAX_TEXT))

    def __str__(self) -> str:
        where = f"line {self.line}" if self.line is not None else "document"
        return f"{where}: {self.path}: {self.message}" if self.path else f"{where}: {self.message}"


class SchemaError(ValueError):
    """A document the schema refuses. Each issue carries the 1-based line of the offending key."""

    def __init__(self, issues: Sequence[Issue], source: str = "<string>") -> None:
        shown = list(issues)
        if len(shown) > MAX_ISSUES + 1:  # one more is the loader's own "N more" summary
            more = len(shown) - MAX_ISSUES
            shown = [*shown[:MAX_ISSUES], Issue(None, "", f"{more} more problems not shown")]
        self.issues = tuple(shown)
        self.source = _clean(source, 200)
        super().__init__("\n".join(f"{self.source}: {i}" for i in self.issues))

    def __reduce__(self) -> tuple[Any, ...]:
        return (SchemaError, (self.issues, self.source))


class _Refusal(Exception):
    def __init__(self, line: int | None, message: str) -> None:
        super().__init__(message)
        self.line = line
        self.message = message


_T = "tag:yaml.org,2002:"
_ALLOWED_TAGS = frozenset(
    _T + t for t in ("str", "int", "float", "bool", "null", "map", "seq", "timestamp")
)
_STR_TAG, _BOOL_TAG, _MERGE_TAG = _T + "str", _T + "bool", _T + "merge"
_INT_TAG, _FLOAT_TAG = _T + "int", _T + "float"
_ON_WORDS = {"on", "On", "ON"}
# YAML 1.1 reads all of these as booleans; YAML 1.2 and JSON read them as text. Only true and
# false are booleans here, and as a plain key any of these words is refused, not read as text.
_YAML11_BOOL_WORDS = frozenset(
    {"yes", "Yes", "YES", "no", "No", "NO", "true", "True", "TRUE", "false", "False", "FALSE"}
    | {"on", "On", "ON", "off", "Off", "OFF"}
)
_BOOL_RE = re.compile(r"^(?:true|false)$")
_INT_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
_FLOAT_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+(?:[eE][-+]?[0-9]+)?|[eE][-+]?[0-9]+)$")


def _construct_bool(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> bool:
    if node.value not in ("true", "false"):
        raise ValueError(f"{node.value!r} is not true or false")
    return bool(node.value == "true")


def _construct_int(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> int:
    if not _INT_RE.match(node.value):
        raise ValueError(f"{node.value!r} is not a plain decimal integer")
    return int(node.value)


def _construct_float(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> float:
    if not (_FLOAT_RE.match(node.value) or _INT_RE.match(node.value)):
        raise ValueError(f"{node.value!r} is not a plain decimal number")
    return float(node.value)


class _Loader(yaml.SafeLoader):
    """SafeLoader for a strict subset: it records instead of swallowing bad keys and tags."""

    yaml_implicit_resolvers = {
        first: [(tag, rx) for tag, rx in rules if tag not in (_INT_TAG, _FLOAT_TAG, _BOOL_TAG)]
        for first, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self.problems: list[Issue] = []
        self.dropped = 0
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        line = self.peek_event().start_mark.line + 1  # type: ignore[no-untyped-call]
        if self.check_event(yaml.AliasEvent):
            raise _Refusal(line, "YAML aliases are not allowed; write the value out")
        self._depth += 1
        try:
            if self._depth > MAX_DEPTH:
                raise _Refusal(line, f"nesting is deeper than {MAX_DEPTH} levels")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_object(self, node: yaml.Node, deep: bool = False) -> Any:
        line = node.start_mark.line + 1
        if node.tag not in _ALLOWED_TAGS:
            self._note(line, f"the YAML tag {node.tag} is not allowed; use plain values")
            return None
        try:
            return super().construct_object(node, deep=True)
        except ValueError as exc:  # our own constructors, and the standard date errors
            self._note(line, f"invalid {node.tag.rsplit(':', 1)[-1]} value: {exc}")
            return None
        except (TypeError, OverflowError, KeyError, AttributeError):
            # PyYAML's own message names its internals; say what is wrong, not how it failed
            kind = node.tag.rsplit(":", 1)[-1]
            self._note(line, f"not a valid {kind} value")
            return None

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        first_line: dict[str, int] = {}
        for key_node, value_node in node.value:
            line = key_node.start_mark.line + 1
            if not isinstance(key_node, yaml.ScalarNode):
                self._note(line, "keys must be plain strings; complex keys are not allowed")
                continue
            if key_node.style is None and key_node.value in _YAML11_BOOL_WORDS:
                self._note(line, self._bad_key(key_node))
                continue
            if key_node.tag == _MERGE_TAG:
                self._note(line, "merge keys (<<) are not allowed; write the keys out")
                continue
            if key_node.tag not in _ALLOWED_TAGS:
                self._note(line, f"the YAML tag {key_node.tag} is not allowed; use plain values")
                continue
            if key_node.tag != _STR_TAG:
                self._note(line, self._bad_key(key_node))
                continue
            key = key_node.value
            if key in out:
                self._note(
                    line,
                    f"duplicate key {key!r}; the first one is at line {first_line[key]}",
                )
                continue
            first_line[key] = line
            out[key] = self.construct_object(value_node, deep=True)
        return out

    def _note(self, line: int, message: str) -> None:
        if len(self.problems) < MAX_ISSUES:
            self.problems.append(Issue(line, "", message))
        else:
            self.dropped += 1

    @staticmethod
    def _bad_key(key_node: yaml.ScalarNode) -> str:
        raw = key_node.value
        if key_node.value in _YAML11_BOOL_WORDS:
            hint = (
                " The edge key is `next`, not `on`: YAML 1.1 parsers such as PyYAML read a bare "
                "`on` as true."
                if raw in _ON_WORDS
                else ""
            )
            return (
                f"key {raw!r} is read as a YAML boolean by many parsers, not a string.{hint} "
                f"Quote it if you mean the text, or rename it."
            )
        kind = key_node.tag.rsplit(":", 1)[-1]
        return f"key {raw!r} is read as a YAML {kind}, not a string; keys must be strings"


_Loader.add_implicit_resolver(_INT_TAG, _INT_RE, list("-0123456789"))
_Loader.add_implicit_resolver(_FLOAT_TAG, _FLOAT_RE, list("-0123456789"))
_Loader.add_implicit_resolver(_BOOL_TAG, _BOOL_RE, list("tf"))
_Loader.add_constructor(_BOOL_TAG, _construct_bool)
_Loader.add_constructor(_INT_TAG, _construct_int)
_Loader.add_constructor(_FLOAT_TAG, _construct_float)

Loc = tuple[str | int, ...]


def _line_map(node: Any, path: Loc = ()) -> dict[Loc, int]:
    """Line of every path: a key's line for its path, a list item's line for its index."""
    lines: dict[Loc, int] = {path: node.start_mark.line + 1}
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if not isinstance(k, yaml.ScalarNode):
                continue
            lines.update(_line_map(v, (*path, k.value)))
            lines[(*path, k.value)] = k.start_mark.line + 1
    elif isinstance(node, yaml.SequenceNode):
        for i, v in enumerate(node.value):
            lines.update(_line_map(v, (*path, i)))
    return lines


def _fmt_path(path: Loc) -> str:
    out = ""
    for el in path:
        out += f"[{el}]" if isinstance(el, int) else (f".{el}" if out else el)
    return out


def _null_issues(data: Any, lines: dict[Loc, int], path: Loc = ()) -> list[Issue]:
    found: list[Issue] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if v is None:
                found.append(
                    Issue(
                        lines.get((*path, k)),
                        _fmt_path((*path, k)),
                        _NULL_HELP,
                    )
                )
            else:
                found.extend(_null_issues(v, lines, (*path, k)))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            found.extend(_null_issues(v, lines, (*path, i)))
    return found


def _encodes(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _surrogate_issues(data: Any, lines: dict[Loc, int], path: Loc = ()) -> list[Issue]:
    """A lone surrogate loads from YAML but cannot be written out again, so refuse it anywhere."""
    found: list[Issue] = []
    if isinstance(data, str):
        if not _encodes(data):
            found.append(Issue(lines.get(path), _fmt_path(path), "contains a lone surrogate"))
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and not _encodes(k):
                found.append(Issue(lines.get((*path, k)), "", "a key contains a lone surrogate"))
            found.extend(_surrogate_issues(v, lines, (*path, k)))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            found.extend(_surrogate_issues(v, lines, (*path, i)))
    return found


_HINTS = {
    "auto_approve": " Timeouts never approve and no key can make them; a gate waits for a person.",
    "on": " The edge key is `next`.",
}


def _resolve(
    loc: tuple[str | int, ...],
    data: Any,
    lines: dict[Loc, int],
    *,
    discriminated: bool,
    keep_last: bool,
) -> tuple[Loc, int | None]:
    """Map a pydantic location to a path present in the document.

    Pydantic puts union labels (``constrained-str``, a stage's kind) and ``[key]`` into locations;
    those are not in the document and are dropped. Only a missing or unknown key, which is by
    definition absent from the document, keeps its last element.
    """
    path: Loc = ()
    node: Any = data
    last = len(loc) - 1
    tag_skipped = False
    for i, el in enumerate(loc):
        child = (*path, el)
        is_tag = (
            discriminated  # only a Workflow stage is a discriminated union
            and not tag_skipped
            and len(path) == 2
            and path[0] == "stages"
            and isinstance(node, dict)
            and node.get("kind") == el
            and i < last
        )
        if is_tag:
            tag_skipped = True  # the label comes first, once; a field may share its name
            continue
        if child in lines:
            path, node = child, _child(node, el)
        elif i == last and keep_last:
            path = child
    probe = path
    while probe not in lines and probe:
        probe = probe[:-1]
    return path, lines.get(probe)


def _child(node: Any, key: str | int) -> Any:
    if isinstance(node, dict):
        return node.get(key)
    if isinstance(node, list) and isinstance(key, int) and 0 <= key < len(node):
        return node[key]
    return None


def _issues_from(
    err: ValidationError, data: Any, lines: dict[Loc, int], *, discriminated: bool
) -> list[Issue]:
    grouped: dict[tuple[str, int | None], list[str]] = {}
    for e in err.errors():
        kind = e["type"]
        path, line = _resolve(
            tuple(e["loc"]),
            data,
            lines,
            discriminated=discriminated,
            keep_last=kind in ("extra_forbidden", "missing"),
        )
        if kind == "union_tag_invalid" and (*path, "kind") in lines:
            path = (*path, "kind")
            line = lines[path]
        key = path[-1] if path else ""
        if kind == "extra_forbidden":
            hint = _HINTS.get(str(key), "")
            msg = f"unknown key {key!r}.{hint} Check the spelling against the schema"
        elif kind == "missing":
            msg = f"missing required key {key!r}"
        elif kind in ("union_tag_invalid", "union_tag_not_found"):
            msg = f"stage kind must be one of: {', '.join(STAGE_KINDS)}"
        else:
            msg = str(e["msg"]).removeprefix("Value error, ")
        bucket = grouped.setdefault((_fmt_path(path), line), [])
        if msg not in bucket:
            bucket.append(msg)
    return [Issue(line, p, " / or ".join(msgs)) for (p, line), msgs in grouped.items()]


def _line_at(text: str, position: int) -> int:
    return text.count("\n", 0, max(position, 0)) + 1


def load_document(text: str | bytes, *, source: str = "<string>") -> Document:
    """Parse and validate one YAML document, dispatching on ``kind``.

    Raises ``SchemaError`` for anything it refuses, with the line of each problem where one is
    known. No other exception type is part of the contract.
    """
    if not isinstance(text, str | bytes):
        raise SchemaError(
            [Issue(None, "", f"the document must be text or bytes, not {type(text).__name__}")],
            source,
        )
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            line = exc.object[: exc.start].count(b"\n") + 1
            raise SchemaError([Issue(line, "", "the file is not valid UTF-8")], source) from None
    try:
        return _load(text, source)
    except SchemaError:
        raise
    except (RecursionError, ValueError, TypeError, OverflowError) as exc:
        # Defence in depth: the loader and models are meant to turn these into issues themselves.
        raise SchemaError(
            [Issue(None, "", f"the document could not be read ({type(exc).__name__})")], source
        ) from None


def _load(text: str, source: str) -> Document:
    loader: _Loader | None = None
    try:
        try:
            loader = _Loader(text)
            node = loader.get_single_node()
        except yaml.composer.ComposerError as exc:
            if exc.context and "single document" in exc.context:
                mark = exc.problem_mark
                raise _Refusal(
                    mark.line + 1 if mark else None,
                    "only one document is allowed per file; remove the extra `---`",
                ) from exc
            raise
        if node is None:
            raise _Refusal(None, "empty document")
        lines = _line_map(node)
        data = loader.construct_document(node)
    except _Refusal as r:
        raise SchemaError([Issue(r.line, "", r.message)], source) from None
    except yaml.reader.ReaderError as exc:
        raise SchemaError(
            [Issue(_line_at(text, exc.position), "", f"unreadable character: {exc.reason}")],
            source,
        ) from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        why = getattr(exc, "problem", None) or str(exc)
        raise SchemaError(
            [Issue(mark.line + 1 if mark else None, "", f"YAML syntax error: {why}")], source
        ) from None
    finally:
        if loader is not None:
            loader.dispose()
    if loader.problems:
        more = (
            [Issue(None, "", f"{loader.dropped} more problems not shown")] if loader.dropped else []
        )
        raise SchemaError([*loader.problems, *more], source)
    if not isinstance(data, dict):
        raise SchemaError([Issue(1, "", "the document must be a mapping")], source)
    if data.get("apiVersion") != API_VERSION:
        raise SchemaError(
            [
                Issue(
                    lines.get(("apiVersion",), 1), "apiVersion", f"apiVersion must be {API_VERSION}"
                )
            ],
            source,
        )
    model = _KINDS.get(str(data.get("kind")))
    if model is None:
        raise SchemaError(
            [Issue(lines.get(("kind",), 1), "kind", f"kind must be one of: {', '.join(_KINDS)}")],
            source,
        )
    lone = _surrogate_issues(data, lines)
    if lone:
        raise SchemaError(lone, source)
    if model is not WorkflowOverlay:
        nulls = _null_issues(data, lines)
        if nulls:
            raise SchemaError(nulls, source)
    try:
        return model.model_validate(data)
    except ValidationError as err:
        issues = _issues_from(err, data, lines, discriminated=model is Workflow)
        raise SchemaError(issues, source) from None


def load_workflow(text: str | bytes, *, source: str = "<string>") -> Workflow:
    doc = load_document(text, source=source)
    if not isinstance(doc, Workflow):
        raise SchemaError([Issue(1, "kind", f"expected kind Workflow, got {doc.kind}")], source)
    return doc


# --- JSON Schema -----------------------------------------------------------------------------

_FILES: dict[str, type[Document]] = {
    "workflow": Workflow,
    "workflow-overlay": WorkflowOverlay,
    "team-config": TeamConfig,
    "org-policy": OrgPolicy,
}

EDITOR_NOTE = (
    "Editor hints only. This schema is looser than the loader: it cannot express that a date is "
    "real, a timezone or branch name is valid, which outcomes an effect has, or that an instant "
    "carries an offset. A document that validates here may still be refused by "
    "sto.config.schema.load_document, which is the authority."
)


def _drop_null(props: dict[str, Any]) -> None:
    for prop in props.values():
        any_of = prop.get("anyOf")
        if any_of:
            rest = [b for b in any_of if b != {"type": "null"}]
            if len(rest) != len(any_of):
                del prop["anyOf"]
                if len(rest) == 1:
                    prop.update(rest[0])
                else:
                    prop["anyOf"] = rest
        if prop.get("default", 0) is None:
            del prop["default"]


def _close_maps(node: Any) -> None:
    """A map with constrained keys must also refuse keys outside the pattern."""
    if isinstance(node, dict):
        if "patternProperties" in node and "additionalProperties" not in node:
            node["additionalProperties"] = False
        for value in node.values():
            _close_maps(value)
    elif isinstance(node, list):
        for value in node:
            _close_maps(value)


def _fix_lengths(node: Any) -> None:
    """Pydantic words a length limit on a wrapped tuple or map as ``minLength``; fix the word."""
    if isinstance(node, dict):
        if "minLength" in node and node.get("type") == "array":
            node["minItems"] = node.pop("minLength")
        elif "minLength" in node and node.get("type") == "object":
            node["minProperties"] = node.pop("minLength")
        elif "minLength" in node and "anyOf" in node:  # an optional field in an overlay
            for branch in node["anyOf"]:
                word = {"array": "minItems", "object": "minProperties"}.get(branch.get("type"))
                if word:
                    branch[word] = node.pop("minLength")
                    break
        for value in node.values():
            _fix_lengths(value)
    elif isinstance(node, list):
        for value in node:
            _fix_lengths(value)


def json_schemas() -> dict[str, dict[str, Any]]:
    """One JSON Schema per document kind, for editors. Closed objects, no null in full documents."""
    out: dict[str, dict[str, Any]] = {}
    for name, model in _FILES.items():
        doc = model.model_json_schema(by_alias=True)
        defs = doc.get("$defs", {})
        for title, definition in [(doc.get("title"), doc), *defs.items()]:
            if title and not str(title).endswith("Patch") and title != "WorkflowOverlay":
                _drop_null(definition.get("properties", {}))
        _close_maps(doc)
        _fix_lengths(doc)
        doc["description"] = EDITOR_NOTE
        doc = {"$schema": "https://json-schema.org/draft/2020-12/schema", **doc}
        out[name] = doc
    return out


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or check schemas/*.schema.json")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--dir", type=Path, default=Path(__file__).parents[3] / "schemas")
    args = parser.parse_args(argv)
    stale: list[Path] = []
    for name, doc in json_schemas().items():
        path: Path = args.dir / f"{name}.schema.json"
        text = render(doc)
        if args.write:
            args.dir.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        elif not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(path)
    for path in stale:
        print(f"stale or missing: {path}; run `uv run python -m sto.config.schema --write`")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
