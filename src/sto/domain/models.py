"""Frozen base models for subject, decision, step, gate, run and effect. No I/O."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from .ids import DecisionId, EffectId, GateId, RunId
from .states import EffectStatus, GateStatus, RunStatus


@dataclass(frozen=True)
class Subject:
    """What a gate approves (PLAN 4). ``pre_push`` subjects have a ``base_sha``, no ``head_sha``."""

    patch_id: str
    ticket_revision: str
    head_sha: str | None = None
    base_sha: str | None = None
    evidence_digest: str | None = None
    attention_digest: str | None = None
    merge_sha: str | None = None

    def __post_init__(self) -> None:
        if not self.patch_id or not self.ticket_revision:
            raise ValueError("subject needs patch_id and ticket_revision")
        if (self.head_sha is None) == (self.base_sha is None):
            raise ValueError("subject has exactly one of head_sha and base_sha")

    @classmethod
    def pre_push(cls, *, base_sha: str, patch_id: str, ticket_revision: str) -> Subject:
        return cls(patch_id=patch_id, ticket_revision=ticket_revision, base_sha=base_sha)

    def digest(self) -> str:
        blob = json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


class DecisionKind(StrEnum):
    APPROVE = "approve"
    REQUEST_CHANGES = "request_changes"
    REJECT = "reject"
    RETEST = "retest"

    @property
    def is_negative(self) -> bool:
        """Negative decisions are exempt from the digest match (PLAN 4)."""
        return self is not DecisionKind.APPROVE


@dataclass(frozen=True)
class Decision:
    id: DecisionId
    gate_id: GateId
    round: int
    actor: str
    surface: str
    kind: DecisionKind
    subject_digest: str
    comment: str = ""

    def __post_init__(self) -> None:
        if self.round < 1:
            raise ValueError("round starts at 1")
        if not self.actor:
            raise ValueError("decision needs an actor")


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
class Gate:
    id: GateId
    run_id: RunId
    name: str
    round: int
    subject: Subject
    status: GateStatus = GateStatus.OPEN


@dataclass(frozen=True)
class Run:
    id: RunId
    team: str
    status: RunStatus = RunStatus.QUEUED
    version: int = 0


class EffectClass(StrEnum):
    INTERNAL = "internal"
    SCOPED = "scoped"
    GATED = "gated"
    EXPOSING = "exposing"


@dataclass(frozen=True)
class Effect:
    id: EffectId
    run_id: RunId
    type: str
    klass: EffectClass
    idempotency_key: str
    status: EffectStatus = EffectStatus.PLANNED
    requires_gates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.klass is EffectClass.GATED and not self.requires_gates:
            raise ValueError("a gated effect needs a non-empty requires_gates")


def effect_key(run: RunId, stage: str, visit: int, effect_type: str, subject_digest: str) -> str:
    """Default idempotency key (PLAN 6.3): (run, stage, visit, effect type, subject digest)."""
    raw = f"{run}|{stage}|{visit}|{effect_type}|{subject_digest}"
    return hashlib.sha256(raw.encode()).hexdigest()
