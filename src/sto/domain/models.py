"""Frozen base models for subject, decision, step, gate, run and effect. No I/O.

Records are rebuilt from the store, so ``__post_init__`` coerces enum and tuple fields and
validates. ``advance`` is the checked way to change a status; ``dataclasses.replace`` can still
set any status (see ``states``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Any

from .ids import DecisionId, EffectId, GateId, RunId
from .states import EffectStatus, GateStatus, RunStatus, StepStatus, transition


def _enum[E: Enum](cls: type[E], value: object) -> E:
    return value if isinstance(value, cls) else cls(value)


def _strs(name: str, value: object) -> tuple[str, ...]:
    if isinstance(value, str | bytes) or not hasattr(value, "__iter__"):
        raise TypeError(f"{name} must be a sequence of strings, not {type(value).__name__}")
    out = tuple(value)
    if any(not isinstance(v, str) or not v.strip() for v in out):
        raise ValueError(f"{name} must not contain blank entries")
    return out


def _set(obj: object, **values: Any) -> None:
    for k, v in values.items():
        object.__setattr__(obj, k, v)


@dataclass(frozen=True)
class Subject:
    """What a gate approves (PLAN 4). Two shapes:

    * head subject: ``head_sha``, ``patch_id``, ``evidence_digest``, ``attention_digest``,
      ``ticket_revision`` (all required); ``merge_sha`` is recorded after a merge.
    * pre-push subject: ``base_sha``, ``patch_id``, ``ticket_revision`` only.
    """

    patch_id: str
    ticket_revision: str
    head_sha: str | None = None
    base_sha: str | None = None
    evidence_digest: str | None = None
    attention_digest: str | None = None
    merge_sha: str | None = None

    def __post_init__(self) -> None:
        for name in ("patch_id", "ticket_revision"):
            if not getattr(self, name):
                raise ValueError(f"subject {name} must be non-empty")
        for f in dataclasses.fields(self):
            if getattr(self, f.name) == "":
                raise ValueError(f"subject {f.name} must not be an empty string")
        if (self.head_sha is None) == (self.base_sha is None):
            raise ValueError("subject has exactly one of head_sha and base_sha")
        if self.head_sha is not None:
            if self.evidence_digest is None or self.attention_digest is None:
                raise ValueError("subject with head_sha needs evidence_digest and attention_digest")
        elif any(
            v is not None for v in (self.evidence_digest, self.attention_digest, self.merge_sha)
        ):
            raise ValueError(
                "pre-push subject has no evidence_digest, attention_digest or merge_sha"
            )

    @classmethod
    def pre_push(cls, *, base_sha: str, patch_id: str, ticket_revision: str) -> Subject:
        return cls(patch_id=patch_id, ticket_revision=ticket_revision, base_sha=base_sha)

    def digest(self) -> str:
        """SHA-256 of a versioned payload of the approval inputs (ADR-0005 decision 1).

        ``merge_sha`` is excluded (recorded after approval) and unset fields are omitted, so
        neither a merge nor a later added optional field changes an existing digest.
        """
        payload: dict[str, object] = {"v": 1}
        for name in (
            "head_sha",
            "base_sha",
            "patch_id",
            "evidence_digest",
            "attention_digest",
            "ticket_revision",
        ):
            value = getattr(self, name)
            if value is not None:
                payload[name] = value
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


class DecisionKind(StrEnum):
    APPROVE = "approve"
    REQUEST_CHANGES = "request_changes"
    REJECT = "reject"
    RETEST = "retest"
    WAIVE = "waive"  # approves with recorded waivers (PLAN 4.2), so it is NOT a veto

    @property
    def is_negative(self) -> bool:
        """Negative decisions are exempt from the digest match (PLAN 4, ADR-0005 #2)."""
        return self in _NEGATIVE


_NEGATIVE = frozenset({DecisionKind.REQUEST_CHANGES, DecisionKind.REJECT, DecisionKind.RETEST})


class Surface(StrEnum):
    UI = "ui"
    SLACK = "slack"
    GITHUB = "github"


class GateType(StrEnum):
    REVIEW = "review"
    QA = "qa"
    CUSTOM = "custom"


@dataclass(frozen=True)
class Decision:
    id: DecisionId
    gate_id: GateId
    round: int
    actor: str
    surface: Surface
    kind: DecisionKind
    subject_digest: str
    comment: str = ""

    def __post_init__(self) -> None:
        _set(self, surface=_enum(Surface, self.surface), kind=_enum(DecisionKind, self.kind))
        if self.round < 1:
            raise ValueError("decision round starts at 1")
        if not self.actor:
            raise ValueError("decision needs an actor")
        if self.kind is not DecisionKind.APPROVE and not self.comment.strip():
            raise ValueError(f"a {self.kind.value} decision needs a comment")
        if not self.kind.is_negative and not self.subject_digest:
            raise ValueError("an approving decision needs a subject_digest")


@dataclass(frozen=True)
class StepKey:
    run_id: RunId
    stage: str
    visit: int
    attempt: int = 1

    def __post_init__(self) -> None:
        if not self.stage or self.visit < 1 or self.attempt < 1:
            raise ValueError("invalid step key")


@dataclass(frozen=True)
class Step:
    """PLAN 11: stage, attempt, fence, session ID, status, usage, artifact refs."""

    key: StepKey
    fence: int = 0
    session_id: str | None = None
    status: StepStatus = StepStatus.PENDING
    usage: tuple[tuple[str, int], ...] = ()
    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _set(
            self,
            status=_enum(StepStatus, self.status),
            artifact_refs=_strs("artifact_refs", self.artifact_refs),
            usage=tuple((str(k), int(v)) for k, v in self.usage),
        )
        if self.fence < 0:
            raise ValueError("step fence must be >= 0")

    def advance(self, target: StepStatus) -> Step:
        return dataclasses.replace(self, status=transition(self.status, target))


@dataclass(frozen=True)
class Gate:
    id: GateId
    run_id: RunId
    name: str
    type: GateType
    round: int
    subject: Subject
    status: GateStatus = GateStatus.OPEN
    closed_by: str | None = None

    def __post_init__(self) -> None:
        _set(self, type=_enum(GateType, self.type), status=_enum(GateStatus, self.status))
        if self.round < 1:
            raise ValueError("gate round starts at 1")
        if not self.name.strip():
            raise ValueError("gate name must be non-empty")
        if self.status.is_open and self.closed_by is not None:
            raise ValueError("an open gate has no closed_by")

    @property
    def is_open(self) -> bool:
        return self.status.is_open

    def advance(self, target: GateStatus, *, closed_by: str | None = None) -> Gate:
        return dataclasses.replace(
            self,
            status=transition(self.status, target),
            closed_by=closed_by if closed_by is not None else self.closed_by,
        )


@dataclass(frozen=True)
class Run:
    id: RunId
    team: str
    status: RunStatus = RunStatus.QUEUED
    version: int = 0
    stage: str | None = None
    workflow_version: str | None = None
    blocked_reason: str | None = None  # a name registered in BLOCKED_REASONS by its module
    incident: bool = False  # DONE + incident == done_with_incident (PLAN 6.2)

    def __post_init__(self) -> None:
        _set(self, status=_enum(RunStatus, self.status))
        if not self.team:
            raise ValueError("run needs a team")
        if self.version < 0:
            raise ValueError("run version must be >= 0")
        if (self.status is RunStatus.BLOCKED) != (self.blocked_reason is not None):
            raise ValueError("blocked_reason is set exactly when the run is BLOCKED")
        if self.blocked_reason is not None and not self.blocked_reason.strip():
            raise ValueError("blocked_reason must be non-empty")
        if self.incident and self.status is not RunStatus.DONE:
            raise ValueError("incident is only valid on a DONE run (done_with_incident)")

    def advance(
        self, target: RunStatus, *, blocked_reason: str | None = None, incident: bool = False
    ) -> Run:
        return dataclasses.replace(
            self,
            status=transition(self.status, target),
            blocked_reason=blocked_reason,
            incident=incident,
        )


class EffectClass(StrEnum):
    INTERNAL = "internal"
    SCOPED = "scoped"
    GATED = "gated"
    EXPOSING = "exposing"


@dataclass(frozen=True)
class Receipt:
    """External ID and URL plus a read-back result (PLAN 6.3). Simulated writes are labelled."""

    external_id: str
    url: str
    read_back_verified: bool
    simulated: bool = False

    def __post_init__(self) -> None:
        if not self.external_id:
            raise ValueError("receipt needs an external_id")


_NO_RECEIPT = frozenset({EffectStatus.PLANNED, EffectStatus.ATTEMPTING, EffectStatus.RETRYING})


@dataclass(frozen=True)
class Effect:
    id: EffectId
    run_id: RunId
    type: str
    stage: str
    visit: int
    klass: EffectClass
    idempotency_key: str
    status: EffectStatus = EffectStatus.PLANNED
    requires_gates: tuple[str, ...] = ()
    decision_ids: tuple[DecisionId, ...] = ()  # approvals a gated claim relied on (ADR-0011)
    subject_digest: str | None = None
    receipt: Receipt | None = None

    def __post_init__(self) -> None:
        _set(
            self,
            klass=_enum(EffectClass, self.klass),
            status=_enum(EffectStatus, self.status),
            requires_gates=_strs("requires_gates", self.requires_gates),
            decision_ids=tuple(self.decision_ids),
        )
        if not self.type or not self.stage or not self.idempotency_key:
            raise ValueError("effect needs type, stage and idempotency_key")
        if self.visit < 1:
            raise ValueError("effect visit starts at 1")
        if self.klass is EffectClass.GATED and not self.requires_gates:
            raise ValueError("a gated effect needs a non-empty requires_gates")
        if self.klass is not EffectClass.GATED and self.requires_gates:
            raise ValueError("requires_gates is only valid on a gated effect")
        if self.status is EffectStatus.CONFIRMED:
            if self.receipt is None:
                raise ValueError("a CONFIRMED effect needs a receipt")
            if not self.receipt.read_back_verified:
                raise ValueError("a CONFIRMED effect needs a receipt with read-back")
        elif self.status in _NO_RECEIPT and self.receipt is not None:
            raise ValueError(f"a {self.status.value} effect cannot hold a receipt")

    def advance(self, target: EffectStatus, *, receipt: Receipt | None = None) -> Effect:
        return dataclasses.replace(
            self,
            status=transition(self.status, target),
            receipt=receipt if receipt is not None else self.receipt,
        )


def effect_key(run: RunId, stage: str, visit: int, effect_type: str, subject_digest: str) -> str:
    """Default idempotency key (PLAN 6.3, ADR-0011): hash of canonical JSON of the 5-tuple."""
    raw = json.dumps([str(run), stage, visit, effect_type, subject_digest], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()
