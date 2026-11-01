"""Frozen base models for subject, decision, step, gate, run and effect. No I/O.

Construction validates: IDs must be the exact ID class, nested records the exact record class,
required strings non-blank, counters real non-negative ints. Enum and tuple fields are coerced,
so a record rebuilt from its wire form (``from_wire``, the inverse of ``to_wire``) is checked the
same way as one built in code. ``advance`` is the checked way to change a status;
``dataclasses.replace`` can still set any status (see ``states``).

Deliberately NOT here (they live in module-owned records, so nothing later edits ``domain/``):
gate eligible snapshot, extensions and timer IDs; run budget state. Step usage, fence and session
ID are present only as plain data; their meaning belongs to the agents and budget modules.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Any

from .ids import DecisionId, EffectId, GateId, RunId, Ulid
from .states import EffectStatus, GateStatus, RunStatus, StepStatus, transition


def _enum[E: Enum](cls: type[E], value: object) -> E:
    return value if isinstance(value, cls) else cls(value)


def _set(obj: object, **values: Any) -> None:
    for k, v in values.items():
        object.__setattr__(obj, k, v)


def _str(label: str, value: object, *, blank_ok: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string, not {type(value).__name__}")
    if not blank_ok and not value.strip():
        raise ValueError(f"{label} must be non-blank")
    return value


def _opt_str(label: str, value: object) -> str | None:
    return None if value is None else _str(label, value)


def _int(label: str, value: object, minimum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an int, not {type(value).__name__}")
    if value < minimum:
        raise ValueError(f"{label} must be >= {minimum}")
    return value


def _bool(label: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a bool, not {type(value).__name__}")
    return value


def _id[U: Ulid](label: str, cls: type[U], value: object) -> U:
    if type(value) is not cls:
        raise TypeError(f"{label} must be a {cls.__name__}, not {type(value).__name__}")
    return value


def _rec[T](label: str, cls: type[T], value: object) -> T:
    if not isinstance(value, cls):
        raise TypeError(f"{label} must be a {cls.__name__}, not {type(value).__name__}")
    return value


def _seq(label: str, value: object) -> tuple[Any, ...]:
    if isinstance(value, str | bytes) or not hasattr(value, "__iter__"):
        raise TypeError(f"{label} must be a sequence, not {type(value).__name__}")
    return tuple(value)


def _strs(label: str, value: object) -> tuple[str, ...]:
    out = _seq(label, value)
    for v in out:
        if not isinstance(v, str):
            raise TypeError(f"{label} must contain strings")
        if not v.strip():
            raise ValueError(f"{label} must not contain blank entries")
    return out


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
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if value is not None or f.name in ("patch_id", "ticket_revision"):
                _str(f"subject {f.name}", value)
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
        """SHA-256 of a versioned payload of the approval inputs (PLAN 4 subject, ADR-0005 #1).

        The inputs are PLAN 4's subject fields (``attention_digest``, and ``base_sha`` for a
        pre-push subject) plus ADR-0005's. ``merge_sha`` is excluded (recorded after approval)
        and unset fields are omitted, so neither a merge nor a later added optional field changes
        an existing digest.
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
    PRE_PUSH = "pre_push"  # PLAN:953, :1696 `type: pre_push`; the schema line at :777 is stale


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
        _id("decision id", DecisionId, self.id)
        _id("decision gate_id", GateId, self.gate_id)
        _set(self, surface=_enum(Surface, self.surface), kind=_enum(DecisionKind, self.kind))
        _int("decision round", self.round, 1)
        _str("decision actor", self.actor)
        _str("decision comment", self.comment, blank_ok=True)
        _str("decision subject_digest", self.subject_digest, blank_ok=True)
        if self.kind is not DecisionKind.APPROVE and not self.comment.strip():
            raise ValueError(f"a {self.kind.value} decision needs a comment")
        if not self.kind.is_negative and not self.subject_digest.strip():
            raise ValueError("an approving decision needs a subject_digest")


@dataclass(frozen=True)
class StepKey:
    run_id: RunId
    stage: str
    visit: int
    attempt: int = 1

    def __post_init__(self) -> None:
        _id("step key run_id", RunId, self.run_id)
        _str("step key stage", self.stage)
        _int("step key visit", self.visit, 1)
        _int("step key attempt", self.attempt, 1)


@dataclass(frozen=True)
class Step:
    """PLAN 11: stage, attempt, fence, session ID, status, usage, artifact refs.

    There is no outcome field: a ``needs_info`` result is a SUCCEEDED step plus an outcome
    carried on the step's event.
    """

    key: StepKey
    fence: int = 0
    session_id: str | None = None
    status: StepStatus = StepStatus.PENDING
    usage: tuple[tuple[str, int], ...] = ()
    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _rec("step key", StepKey, self.key)
        usage = []
        for item in _seq("step usage", self.usage):
            name, amount = _seq("step usage item", item)
            usage.append((_str("step usage name", name), _int("step usage", amount, 0)))
        _set(
            self,
            status=_enum(StepStatus, self.status),
            artifact_refs=_strs("step artifact_refs", self.artifact_refs),
            usage=tuple(usage),
        )
        _int("step fence", self.fence, 0)
        _opt_str("step session_id", self.session_id)

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
        _id("gate id", GateId, self.id)
        _id("gate run_id", RunId, self.run_id)
        _set(self, type=_enum(GateType, self.type), status=_enum(GateStatus, self.status))
        _rec("gate subject", Subject, self.subject)
        _int("gate round", self.round, 1)
        _str("gate name", self.name)
        _opt_str("gate closed_by", self.closed_by)
        if self.status.is_open and self.closed_by is not None:
            raise ValueError("an open gate has no closed_by")
        if self.type is GateType.PRE_PUSH and self.subject.head_sha is not None:
            # PLAN 4: a pre_push gate closes before any commit exists, so it has no head_sha.
            raise ValueError("a pre_push gate takes a pre-push subject (base_sha, no head_sha)")

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
    # done_with_incident. PLAN 6.2 says a run that merged unqualified code ends done_with_incident
    # "whichever terminal it reaches, including Stop", so any terminal status may carry the flag.
    # The following sentence ("`DONE` with an incident flag") is narrower; we follow the wider
    # one and add no CANCELLING -> DONE edge.
    incident: bool = False

    def __post_init__(self) -> None:
        _id("run id", RunId, self.id)
        _set(self, status=_enum(RunStatus, self.status))
        _str("run team", self.team)
        _int("run version", self.version, 0)
        _opt_str("run stage", self.stage)
        _opt_str("run workflow_version", self.workflow_version)
        _opt_str("run blocked_reason", self.blocked_reason)
        _bool("run incident", self.incident)
        if (self.status is RunStatus.BLOCKED) != (self.blocked_reason is not None):
            raise ValueError("blocked_reason is set exactly when the run is BLOCKED")
        if self.incident and not self.status.is_terminal:
            raise ValueError("incident is only valid on a terminal run (done_with_incident)")

    def advance(
        self,
        target: RunStatus,
        *,
        blocked_reason: str | None = None,
        incident: bool | None = None,
    ) -> Run:
        return dataclasses.replace(
            self,
            status=transition(self.status, target),
            blocked_reason=blocked_reason,
            incident=self.incident if incident is None else incident,
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
        _str("receipt external_id", self.external_id)
        _str("receipt url", self.url, blank_ok=True)
        _bool("receipt read_back_verified", self.read_back_verified)
        _bool("receipt simulated", self.simulated)


# A gated effect in any other status implies a claim was made, which ADR-0011 says needs a
# decision ID and the subject it was checked against.
_UNCLAIMED = frozenset({EffectStatus.PLANNED, EffectStatus.VOIDED})
_NO_RECEIPT = frozenset({EffectStatus.PLANNED, EffectStatus.ATTEMPTING, EffectStatus.RETRYING})


@dataclass(frozen=True)
class Effect:
    """PLAN 6.3 / 11: class, status, attempts, intent, receipt, frozen subject after a merge.

    ``stage`` is the stage that planned it. An engine-implicit effect (PLAN 6.3: check runs, gate
    notifications, ``pr.close`` on reject, the revert PR) has no stage of its own and passes the
    run's last stage.
    """

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
    attempts: int = 0
    intent: str | None = None  # e.g. a commit SHA recorded before the ref moves (PLAN 6.3)
    frozen_subject: Subject | None = None  # fixed once a merge lands (PLAN 4, 6.4)

    def __post_init__(self) -> None:
        _id("effect id", EffectId, self.id)
        _id("effect run_id", RunId, self.run_id)
        _set(
            self,
            klass=_enum(EffectClass, self.klass),
            status=_enum(EffectStatus, self.status),
            requires_gates=_strs("effect requires_gates", self.requires_gates),
            decision_ids=tuple(
                _id("effect decision_ids entry", DecisionId, d)
                for d in _seq("effect decision_ids", self.decision_ids)
            ),
        )
        _str("effect type", self.type)
        _str("effect stage", self.stage)
        _str("effect idempotency_key", self.idempotency_key)
        _int("effect visit", self.visit, 1)
        _int("effect attempts", self.attempts, 0)
        _opt_str("effect subject_digest", self.subject_digest)
        _opt_str("effect intent", self.intent)
        if self.receipt is not None:
            _rec("effect receipt", Receipt, self.receipt)
        if self.frozen_subject is not None:
            _rec("effect frozen_subject", Subject, self.frozen_subject)
        gated = self.klass is EffectClass.GATED
        if gated and not self.requires_gates:
            raise ValueError("a gated effect needs a non-empty requires_gates")
        if not gated and self.requires_gates:
            raise ValueError("requires_gates is only valid on a gated effect")
        if gated and self.status not in _UNCLAIMED:
            if not self.decision_ids:
                raise ValueError(f"a {self.status.value} gated effect needs decision_ids")
            if self.subject_digest is None:
                raise ValueError(f"a {self.status.value} gated effect needs a subject_digest")
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
