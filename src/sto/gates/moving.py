"""Moving ticket and PR (D3-13, PLAN 4.5, G11): what a change under a run does, at any stage.

Two halves, both small:

* :func:`react` is **pure**. From the run's facts and one event (new commit, edited or closed
  ticket, closed or merged PR) it returns a :class:`Reaction`: what to do to the open gates and
  the run, and what to audit. It reads no store and has no clock. The driver applies the run part
  through the reducer (a ``BLOCK`` is a blocked reason, a ``RETURN_TO_STAGE`` is the
  ``external_commit`` loop, ``CANCEL`` and ``FINISH_WITH_INCIDENT`` end the run); this module
  never edits the reducer or the gate service.
* :func:`apply_reaction` turns the gate part into store ops for one transaction: open gates are
  ``superseded``, the votes of a gate whose ticket changed are deleted, the ``MOVE#state`` item is
  written, and one chained audit entry is added (``record_with_audit``). :func:`check_decision` is
  the decision-time rule a surface calls before ``GateService.decide``: a closed ticket cannot be
  approved and an approval after an edit must acknowledge the new revision.

Rules kept from the gate service and the checks stage:

* **Approvals are tied to head SHAs.** A new commit supersedes every open gate (a superseded gate
  is closed, so ``decide`` refuses with ``gate_closed``) and the run goes back to CI. An approval
  for the old subject can never count for the new one, and a force-pushed PR is just a commit
  that is not ours.
* **Fail closed.** Our own commit is recognised only by the head SHAs we pushed (receipts), our
  own merge only by a merge SHA in a receipt *and* our App as the merge author. An unknown
  author, a missing SHA or an unknown editor counts as outside, never as ours.
* **Well-formed but unsafe events BLOCK rather than raise.** An outside merge, a non-member edit
  and a commit that cannot be routed all give a ``BLOCK`` reaction. Only a malformed event
  (:class:`MovingEventError`) or a stale one (:class:`StaleMovingEventError`) raises, and a
  raise changes nothing.
* **Stale events are refused by run version.** Every event carries the run version its sender
  saw; a different one is refused.

Classification waits while one of our push or update effects is ``ATTEMPTING`` (``DEFER``), so we
never mistake our own commit for a person's.

Wiring that this module does not do (it stays inside its own file): the ingest/reconcile layer
(D4) builds ``MovingFacts`` and events, and the decision surfaces call :func:`check_decision`
beside ``GateService.decide``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sto.domain import (
    DecisionKind,
    Gate,
    GateStatus,
    PermanentError,
    RunId,
    RunStatus,
    from_wire,
    to_wire,
)
from sto.gates.hooks import Reader, record_with_audit, run_pk
from sto.store.ports import Absent, Delete, Key, Op, Put, Scope, VersionIs

__all__ = [
    "AcknowledgementRequiredError",
    "Action",
    "CommitPushed",
    "MoveState",
    "MovingEvent",
    "MovingEventError",
    "MovingFacts",
    "PrClosed",
    "Reaction",
    "StaleMovingEventError",
    "TicketClosed",
    "TicketClosedError",
    "TicketEdited",
    "apply_reaction",
    "check_decision",
    "load_state",
    "react",
]

STATE_KEY_SK = "MOVE#state"
EXTERNAL_COMMIT_LOOP = "external_commit"


class MovingEventError(PermanentError):
    """The event or the facts are malformed (a producer fault). Nothing has changed."""


class StaleMovingEventError(PermanentError):
    """The event was built for another run version than the live one. Nothing has changed."""


class TicketClosedError(PermanentError):
    """A closed ticket cannot be approved (G11)."""

    code = "ticket_closed"


class AcknowledgementRequiredError(PermanentError):
    """The ticket changed since the gate opened: approving needs the new revision acknowledged."""

    code = "ack_required"


class Action(StrEnum):
    NONE = "none"
    DEFER = "defer"  # one of our push effects is ATTEMPTING: classify again when it settles
    RETURN_TO_STAGE = "return_to_stage"
    BLOCK = "block"
    CANCEL = "cancel"
    FINISH_WITH_INCIDENT = "finish_with_incident"


# --- validation -------------------------------------------------------------------------------


def _bad(message: str) -> MovingEventError:
    return MovingEventError(message)


def _text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _bad(f"{label} must be a non-blank string")
    return value


def _opt_text(label: str, value: object) -> str | None:
    return None if value is None else _text(label, value)


def _flag(label: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise _bad(f"{label} must be a bool")
    return value


def _count(label: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _bad(f"{label} must be a non-negative integer")
    return value


def _shas(label: str, value: object) -> frozenset[str]:
    if not isinstance(value, frozenset):
        raise _bad(f"{label} must be a frozenset of strings")
    return frozenset(_text(f"{label} member", v) for v in value)


# --- facts and events -------------------------------------------------------------------------


@dataclass(frozen=True)
class MovingFacts:
    """What the run looks like when the event arrives; built by the driver from the run and its
    receipts.

    ``our_heads`` are the head SHAs our push effects produced, ``our_merges`` the merge SHAs in
    our merge receipts. ``return_stage`` is the workflow's ``on_external_commit`` target, else its
    CI stage (``None`` when it has neither). ``external_commits`` is how many times the
    ``external_commit`` loop has been used, ``external_commit_cap`` its cap (default 3).
    """

    run_version: int
    status: RunStatus
    stage: str | None
    head_sha: str | None
    ticket_revision: str | None
    has_open_gate: bool
    merged: bool
    our_heads: frozenset[str]
    our_merges: frozenset[str]
    push_attempting: bool
    return_stage: str | None
    external_commits: int
    external_commit_cap: int
    app_login: str

    def __post_init__(self) -> None:
        _count("run_version", self.run_version)
        if not isinstance(self.status, RunStatus):
            raise _bad("status must be a RunStatus")
        _opt_text("stage", self.stage)
        _opt_text("head_sha", self.head_sha)
        _opt_text("ticket_revision", self.ticket_revision)
        _flag("has_open_gate", self.has_open_gate)
        _flag("merged", self.merged)
        _shas("our_heads", self.our_heads)
        _shas("our_merges", self.our_merges)
        _flag("push_attempting", self.push_attempting)
        _opt_text("return_stage", self.return_stage)
        _count("external_commits", self.external_commits)
        _count("external_commit_cap", self.external_commit_cap)
        _text("app_login", self.app_login)

    @property
    def ended(self) -> bool:
        return self.status.is_terminal or self.status is RunStatus.CANCELLING


@dataclass(frozen=True)
class CommitPushed:
    """A commit now heads the PR branch (including a force push: it is just a new head)."""

    run_version: int
    sha: str

    def __post_init__(self) -> None:
        _count("run_version", self.run_version)
        _text("sha", self.sha)


@dataclass(frozen=True)
class TicketEdited:
    """The ticket's ``ticket_revision`` (D2-08) moved. ``editor_is_member`` is ``None`` when the
    editor is unknown (the reconciler often sees only a hash
    change); that counts as a non-member."""

    run_version: int
    revision: str
    editor: str | None
    editor_is_member: bool | None

    def __post_init__(self) -> None:
        _count("run_version", self.run_version)
        _text("revision", self.revision)
        _opt_text("editor", self.editor)
        if self.editor_is_member is not None:
            _flag("editor_is_member", self.editor_is_member)


@dataclass(frozen=True)
class TicketClosed:
    run_version: int
    deleted: bool = False

    def __post_init__(self) -> None:
        _count("run_version", self.run_version)
        _flag("deleted", self.deleted)


@dataclass(frozen=True)
class PrClosed:
    """The PR closed. ``merged_by`` is the merge author's login, ``None`` when unknown."""

    run_version: int
    merged: bool
    merge_sha: str | None = None
    merged_by: str | None = None

    def __post_init__(self) -> None:
        _count("run_version", self.run_version)
        _flag("merged", self.merged)
        _opt_text("merge_sha", self.merge_sha)
        _opt_text("merged_by", self.merged_by)
        if not self.merged and (self.merge_sha is not None or self.merged_by is not None):
            raise _bad("a PR that was not merged has no merge_sha or merged_by")


MovingEvent = CommitPushed | TicketEdited | TicketClosed | PrClosed


# --- the pure reaction ------------------------------------------------------------------------


@dataclass(frozen=True)
class Reaction:
    """What to do. ``supersede_gates`` closes every open gate as ``superseded``. ``drop_votes``
    deletes the votes on open gates. ``require_ack`` is the ticket revision a later approval must
    acknowledge. ``record_revision`` is the newest ticket revision seen. ``stage`` and ``loop`` are
    set for ``RETURN_TO_STAGE``; ``reason`` is the blocked reason or the cancel reason."""

    action: Action = Action.NONE
    reason: str | None = None
    stage: str | None = None
    loop: str | None = None
    supersede_gates: bool = False
    drop_votes: bool = False
    require_ack: str | None = None
    record_revision: str | None = None
    ticket_closed: bool = False
    audit_action: str | None = None
    audit_data: Mapping[str, Any] = field(default_factory=dict)

    @property
    def writes(self) -> bool:
        return bool(
            self.supersede_gates
            or self.drop_votes
            or self.require_ack
            or self.record_revision
            or self.ticket_closed
            or self.audit_action
        )


def react(facts: MovingFacts, event: MovingEvent) -> Reaction:
    """The reaction to ``event`` (PLAN 4.5). Raises only for a malformed or stale event."""
    if not isinstance(facts, MovingFacts):
        raise _bad("facts must be MovingFacts")
    if not isinstance(event, CommitPushed | TicketEdited | TicketClosed | PrClosed):
        raise _bad(f"unknown moving event {type(event).__name__}")
    if event.run_version != facts.run_version:
        raise StaleMovingEventError(
            f"event is for run version {event.run_version}, the live version is {facts.run_version}"
        )
    match event:
        case CommitPushed():
            return _commit(facts, event)
        case TicketEdited():
            return _edit(facts, event)
        case TicketClosed():
            return _closed(facts, event)
        case PrClosed():
            return _pr(facts, event)


def _commit(facts: MovingFacts, event: CommitPushed) -> Reaction:
    sha = event.sha
    if sha == facts.head_sha or sha in facts.our_heads:
        return Reaction()  # our own commit, or the head we already hold
    if facts.ended:
        return Reaction()
    if facts.merged:
        # Merged code is immutable; a later push to the branch changes no approval.
        return Reaction(audit_action="moving.commit_after_merge", audit_data={"sha": sha})
    if facts.push_attempting:
        return Reaction(Action.DEFER)  # it may be ours; classify when the effect settles
    data = {"sha": sha, "previous_head": facts.head_sha, "stage": facts.stage}
    if facts.return_stage is None:
        return Reaction(
            Action.BLOCK,
            "external_commit_unroutable",
            supersede_gates=True,
            audit_action="moving.external_commit",
            audit_data=data,
        )
    if facts.external_commits >= facts.external_commit_cap:
        return Reaction(
            Action.BLOCK,
            "loop_exhausted",
            supersede_gates=True,
            audit_action="moving.external_commit",
            audit_data={**data, "loop": EXTERNAL_COMMIT_LOOP, "cap": facts.external_commit_cap},
        )
    return Reaction(
        Action.RETURN_TO_STAGE,
        stage=facts.return_stage,
        loop=EXTERNAL_COMMIT_LOOP,
        supersede_gates=True,
        audit_action="moving.external_commit",
        audit_data=data,
    )


def _edit(facts: MovingFacts, event: TicketEdited) -> Reaction:
    data = {
        "from": facts.ticket_revision,
        "to": event.revision,
        "editor": event.editor,
        "editor_is_member": event.editor_is_member,
    }
    if event.revision == facts.ticket_revision:
        return Reaction()
    if facts.ended:
        return Reaction()
    if facts.merged:
        # After a merge, later gated effects use the subject frozen in the receipt.
        return Reaction(audit_action="moving.ticket_edit_after_merge", audit_data=data)
    if event.editor_is_member is not True or event.editor is None:
        return Reaction(
            Action.BLOCK,
            "ticket_edit_unconfirmed",
            drop_votes=facts.has_open_gate,
            require_ack=event.revision,
            record_revision=event.revision,
            audit_action="moving.ticket_edit_untrusted",
            audit_data=data,
        )
    return Reaction(
        drop_votes=facts.has_open_gate,
        require_ack=event.revision if facts.has_open_gate else None,
        record_revision=event.revision,
        audit_action="moving.ticket_edited",
        audit_data=data,
    )


def _closed(facts: MovingFacts, event: TicketClosed) -> Reaction:
    reason = "ticket_deleted" if event.deleted else "ticket_closed"
    data = {"deleted": event.deleted, "merged": facts.merged}
    if facts.ended:
        return Reaction(ticket_closed=True, audit_action=f"moving.{reason}", audit_data=data)
    action = Action.FINISH_WITH_INCIDENT if facts.merged else Action.CANCEL
    return Reaction(
        action,
        reason,
        supersede_gates=True,
        ticket_closed=True,
        audit_action=f"moving.{reason}",
        audit_data=data,
    )


def _pr(facts: MovingFacts, event: PrClosed) -> Reaction:
    if not event.merged:
        if facts.ended or facts.merged:
            return Reaction()
        return Reaction(
            Action.CANCEL,
            "pr_closed",
            supersede_gates=True,
            audit_action="moving.pr_closed",
            audit_data={},
        )
    ours = (
        event.merge_sha is not None
        and event.merge_sha in facts.our_merges
        and event.merged_by == facts.app_login
    )
    if ours:
        return Reaction()  # recognised from its receipt and author: not a movement
    data = {"merge_sha": event.merge_sha, "merged_by": event.merged_by, "flagged": True}
    return Reaction(
        Action.NONE if facts.ended else Action.BLOCK,
        None if facts.ended else "outside_merge",
        supersede_gates=not facts.ended,
        audit_action="moving.outside_merge",
        audit_data=data,
    )


# --- decision time ----------------------------------------------------------------------------


@dataclass(frozen=True)
class MoveState:
    """What the run remembers between events (``MOVE#state``)."""

    ticket_closed: bool = False
    pending_revision: str | None = None


def check_decision(state: MoveState, kind: DecisionKind, *, acknowledged: str | None) -> None:
    """Refuse an approval the moved ticket forbids. A negative decision is never delayed (the gate
    service exempts it too). ``acknowledged`` is the revision the person confirmed they saw."""
    if kind.is_negative:
        return
    if state.ticket_closed:
        raise TicketClosedError("the ticket is closed, so it cannot be approved")
    pending = state.pending_revision
    if pending is not None and acknowledged != pending:
        raise AcknowledgementRequiredError(
            f"the ticket changed to revision {pending}; acknowledge the change before approving"
        )


# --- store ------------------------------------------------------------------------------------


def _state_key(run_id: RunId) -> Key:
    return Key(run_pk(run_id), STATE_KEY_SK)


def load_state(reader: Reader, scope: Scope, run_id: RunId) -> MoveState:
    item = reader.get(scope, _state_key(run_id))
    if item is None:
        return MoveState()
    pending = item.data.get("pending_revision")
    return MoveState(bool(item.data.get("ticket_closed", False)), pending)


def _open_gates(reader: Reader, scope: Scope, run_id: RunId) -> list[tuple[Any, Gate]]:
    found: list[tuple[Any, Gate]] = []
    cursor: str | None = None
    while True:
        page = reader.query(scope, run_pk(run_id), sk_prefix="GATE#", cursor=cursor)
        for item in page.items:
            gate = from_wire(Gate, item.data)
            if gate.is_open:
                found.append((item, gate))
        cursor = page.cursor
        if cursor is None:
            return found


def apply_reaction(
    reader: Reader, scope: Scope, run_id: RunId, reaction: Reaction, *, actor: str, at: int
) -> list[Op]:
    """The store ops for ``reaction``, for one transaction; empty when it writes nothing.

    Every gate and vote write is conditioned on the version read, and the audit entry moves the
    chain head, so a decision that lands in between fails the transaction: the caller re-reads
    and calls again (the gate is then closed or the votes gone, and the ops shrink).
    """
    if not reaction.writes:
        return []
    ops: list[Op] = []
    open_gates = _open_gates(reader, scope, run_id)
    superseded: list[dict[str, Any]] = []
    if reaction.supersede_gates:
        for item, gate in open_gates:
            closed = gate.advance(GateStatus.SUPERSEDED, closed_by=actor)
            ops.append(Put(item.key, to_wire(closed), VersionIs(item.version)))
            superseded.append({"gate": gate.name, "round": gate.round, "gate_id": str(gate.id)})
    if reaction.drop_votes:
        prefixes = tuple(f"VOTE#{g.name}#{g.round}#" for _, g in open_gates)
        cursor: str | None = None
        while prefixes:
            page = reader.query(scope, run_pk(run_id), sk_prefix="VOTE#", cursor=cursor)
            ops += [
                Delete(i.key, VersionIs(i.version))
                for i in page.items
                if i.key.sk.startswith(prefixes)
            ]
            cursor = page.cursor
            if cursor is None:
                break
    if reaction.ticket_closed or reaction.require_ack or reaction.record_revision:
        existing = reader.get(scope, _state_key(run_id))
        before = load_state(reader, scope, run_id)
        pending = (
            reaction.require_ack
            if reaction.require_ack is not None
            else (None if reaction.record_revision is not None else before.pending_revision)
        )
        ops.append(
            Put(
                _state_key(run_id),
                {
                    "ticket_closed": before.ticket_closed or reaction.ticket_closed,
                    "pending_revision": pending,
                },
                Absent() if existing is None else VersionIs(existing.version),
            )
        )
    data = {
        **reaction.audit_data,
        "action": reaction.action.value,
        "superseded": superseded,
        "votes_dropped": reaction.drop_votes,
    }
    return record_with_audit(
        reader,
        scope,
        run_id,
        action=reaction.audit_action or "moving.applied",
        actor=actor,
        data=data,
        at=at,
        writes=ops,
    )
