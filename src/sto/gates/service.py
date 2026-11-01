"""Gate service v0 (D1-06): open a gate, decide through one function, close exactly once.

* ``open_gate`` is idempotent on ``(run, name, round)`` (the ``GATE#g#round`` key), because the
  reducer's ``OpenGate`` command carries no ID and a driver may replay it. The ID is minted only
  inside a conditional create; a replay finds the stored gate and returns it unchanged.
* ``decide`` is the only way a gate closes (ADR-0005 #7). The close is a conditional write on the
  gate's store version, in **one transaction** with the decision, the audit entry, the outbox
  entry, the invalidation of earlier approvals and whatever the hooks add (PLAN 4.3 rules 3, 4, 6).
  A lost race on a gate that is still open is retried; only a gate that is really closed gives
  ``gate_closed``.
* An approval carries the subject digest the person saw and is refused if the subject has moved;
  a negative decision is exempt, so nothing can delay a veto (ADR-0005 #1, #2).

v0 is single-approver: the first valid decision closes the gate. Quorum, eligibility and
separation of duties arrive through the hooks (D3).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from sto.domain import (
    Decision,
    DecisionId,
    DecisionKind,
    Gate,
    GateId,
    GateStatus,
    GateType,
    OutboxId,
    PermanentError,
    RunId,
    Surface,
    from_wire,
    to_wire,
)
from sto.engine.commands import OpenGate
from sto.gates.hooks import (
    CHAIN_SK,
    GENESIS_HASH,
    AuditEntry,
    AuditWriter,
    ChainedAuditWriter,
    DecideContext,
    GateHooks,
    OpenContext,
    ReadOnly,
    audit_pk,
    entry_hash,
    run_pk,
)
from sto.store.ports import (
    AUDIT,
    Absent,
    ConditionFailedError,
    Item,
    Key,
    Op,
    Put,
    Scope,
    Store,
    TransactionConflictError,
    VersionIs,
    require_scope,
)

MAX_ATTEMPTS = 25
SYSTEM_ACTOR = "system"

_CLOSES_AS = {
    DecisionKind.APPROVE: GateStatus.APPROVED,
    DecisionKind.REQUEST_CHANGES: GateStatus.CHANGES_REQUESTED,
    DecisionKind.REJECT: GateStatus.REJECTED,
    DecisionKind.RETEST: GateStatus.RETEST,
}


class GateError(PermanentError):
    """Base of the gate service's refusals. ``code`` is the stable name the API maps (D1-08)."""

    code = "gate_error"


class GateClosedError(GateError):
    """409 ``gate_closed``: says who closed the gate and how (PLAN 4.3 rule 4)."""

    code = "gate_closed"

    def __init__(self, gate: Gate) -> None:
        self.gate_name = gate.name
        self.round = gate.round
        self.status = gate.status
        self.closed_by = gate.closed_by
        super().__init__(
            f"gate {gate.name!r} round {gate.round} is already {gate.status.value}"
            + (f" (closed by {gate.closed_by})" if gate.closed_by else "")
        )


class StaleSubjectError(GateError):
    """An approval for a subject that is no longer the gate's (PLAN 4: the server refuses it)."""

    code = "stale_subject"


class GateNotFoundError(GateError):
    code = "gate_not_found"


class DecisionNotAllowedError(GateError):
    code = "decision_not_allowed"


class GateConflictError(GateError):
    """``open_gate`` for a triple that already holds a different gate (a bug, not a replay)."""

    code = "gate_conflict"


def gate_key(run_id: RunId, name: str, round: int) -> Key:
    return Key(run_pk(run_id), f"GATE#{name}#{round}")


@dataclass(frozen=True)
class Decided:
    gate: Gate
    decision: Decision


class GateService:
    def __init__(
        self,
        store: Store,
        *,
        hooks: GateHooks | None = None,
        audit: AuditWriter | None = None,
    ) -> None:
        self._store = store
        self._reader = ReadOnly(store)
        self._hooks = hooks if hooks is not None else GateHooks()
        self._audit: AuditWriter = audit if audit is not None else ChainedAuditWriter()

    # --- open -------------------------------------------------------------------------------

    def open_gate(self, scope: Scope, cmd: OpenGate) -> Gate:
        require_scope(scope)
        _check_name(cmd.name)
        key = gate_key(cmd.run_id, cmd.name, cmd.round)
        last: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            existing = self._store.get(scope, key)
            if existing is not None:
                gate = from_wire(Gate, existing.data)
                if gate.subject != cmd.subject or gate.type != cmd.type:
                    raise GateConflictError(
                        f"gate {cmd.name!r} round {cmd.round} already exists with another subject"
                    )
                return gate
            gate = Gate(GateId.new(), cmd.run_id, cmd.name, cmd.type, cmd.round, cmd.subject)
            entry = AuditEntry(
                cmd.run_id,
                "gate.opened",
                SYSTEM_ACTOR,
                {
                    "gate": gate.name,
                    "round": gate.round,
                    "type": gate.type.value,
                    "gate_id": str(gate.id),
                    "subject_digest": gate.subject.digest(),
                },
                _now_ms(),
            )
            own: list[Op] = [
                Put(key, to_wire(gate), Absent()),
                *self._audit.ops(self._reader, scope, entry),
            ]
            hook_ops = self._hooks.open_ops(OpenContext(self._reader, scope, gate))
            try:
                self._store.transact(scope, [*own, *hook_ops])
            except ConditionFailedError as err:
                _raise_if_only_hooks(err, len(own))
                last = err
            except TransactionConflictError as err:
                last = err
                _backoff(attempt)
            else:
                return gate
        assert last is not None
        raise last

    # --- decide -----------------------------------------------------------------------------

    def decide(
        self,
        scope: Scope,
        *,
        run_id: RunId,
        gate: str,
        round: int,
        kind: DecisionKind,
        actor: str,
        surface: Surface,
        subject_digest: str,
        comment: str = "",
    ) -> Decided:
        """The one decision function; every surface calls it (ADR-0005 #7)."""
        require_scope(scope)
        kind = DecisionKind(kind)
        if kind not in _CLOSES_AS:
            raise DecisionNotAllowedError(f"{kind.value} is not available yet")
        key = gate_key(run_id, gate, round)
        decision_id = DecisionId.new()
        last: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            item = self._store.get(scope, key)
            if item is None:
                raise GateNotFoundError(f"no gate {gate!r} round {round} for run {run_id}")
            current = from_wire(Gate, item.data)
            if not current.is_open:
                raise GateClosedError(current)
            if kind is DecisionKind.RETEST and current.type is not GateType.QA:
                raise DecisionNotAllowedError("retest is a QA gate decision")
            decision = Decision(
                decision_id, current.id, round, actor, surface, kind, subject_digest, comment
            )
            # An approval is exactly as strong as the subject it saw; a veto never waits for it.
            if not kind.is_negative and subject_digest != current.subject.digest():
                raise StaleSubjectError(
                    f"the subject of gate {gate!r} round {round} changed; review it again"
                )
            closed = current.advance(_CLOSES_AS[kind], closed_by=actor)
            invalidated = (
                [] if kind is DecisionKind.APPROVE else self._earlier_approvals(scope, current)
            )
            own = self._close_ops(scope, item, closed, decision, invalidated)
            hook_ops = self._hooks.decide_ops(
                DecideContext(self._reader, scope, current, closed, decision)
            )
            try:
                self._store.transact(scope, [*own, *hook_ops])
            except ConditionFailedError as err:
                _raise_if_only_hooks(err, len(own))
                last = err  # re-read: closed now -> gate_closed above; still open -> try again
            except TransactionConflictError as err:
                last = err
                _backoff(attempt)
            else:
                return Decided(closed, decision)
        assert last is not None
        raise last

    # --- internals --------------------------------------------------------------------------

    def _earlier_approvals(self, scope: Scope, closing: Gate) -> list[tuple[Item, Gate]]:
        """Approved instances of the same gate, in this run, that this close voids (rule 3)."""
        page = self._store.query(scope, run_pk(closing.run_id), sk_prefix=f"GATE#{closing.name}#")
        found = []
        for item in page.items:
            other = from_wire(Gate, item.data)
            if (
                other.name == closing.name
                and other.round != closing.round
                and other.status is GateStatus.APPROVED
            ):
                found.append((item, other))
        return found

    def _close_ops(
        self,
        scope: Scope,
        item: Item,
        closed: Gate,
        decision: Decision,
        invalidated: list[tuple[Item, Gate]],
    ) -> list[Op]:
        pk = run_pk(closed.run_id)
        outbox = {
            "kind": "gate.closed",
            "run_id": str(closed.run_id),
            "gate": closed.name,
            "round": closed.round,
            "status": closed.status.value,
            "decision": decision.kind.value,
            "decision_id": str(decision.id),
            "actor": decision.actor,
            "subject": to_wire(closed.subject) if decision.kind is DecisionKind.APPROVE else None,
        }
        entry = AuditEntry(
            closed.run_id,
            "gate.decided",
            decision.actor,
            {
                "gate": closed.name,
                "round": closed.round,
                "gate_id": str(closed.id),
                "decision": decision.kind.value,
                "decision_id": str(decision.id),
                "status": closed.status.value,
                "subject_digest": decision.subject_digest,
                "comment": decision.comment,
                "invalidated_rounds": [g.round for _, g in invalidated],
            },
            _now_ms(),
        )
        ops: list[Op] = [
            # The single close: succeeds only if nobody wrote this gate since it was read.
            Put(item.key, to_wire(closed), VersionIs(item.version)),
            Put(
                Key(pk, f"DEC#{closed.name}#{closed.round}#{decision.id}"),
                to_wire(decision),
                Absent(),
            ),
            Put(Key(pk, f"OUT#{OutboxId.new()}"), outbox, Absent()),
            *self._audit.ops(self._reader, scope, entry),
        ]
        for old_item, old in invalidated:
            ops.append(
                Put(
                    old_item.key,
                    to_wire(old.advance(GateStatus.INVALIDATED)),
                    VersionIs(old_item.version),
                )
            )
        return ops


def verify_audit_chain(store: Store | ReadOnly, scope: Scope, run_id: RunId) -> int:
    """Walk a run's audit table and check sequence, links and hashes against the chain head.
    Returns the number of entries; raises ``ValueError`` on the first break."""
    prev, count = GENESIS_HASH, 0
    for item in store.query(scope, audit_pk(run_id), table=AUDIT).items:
        body = {k: v for k, v in item.data.items() if k != "hash"}
        count += 1
        if body.get("seq") != count or body.get("prev") != prev:
            raise ValueError(f"audit chain broken at entry {count}: sequence or link")
        if entry_hash(body) != item.data.get("hash"):
            raise ValueError(f"audit chain broken at entry {count}: hash mismatch")
        prev = item.data["hash"]
    head = store.get(scope, Key(run_pk(run_id), CHAIN_SK))
    if (head is None) != (count == 0) or (
        head is not None and (head.data["seq"], head.data["hash"]) != (count, prev)
    ):
        raise ValueError("audit chain broken: head does not match the last entry")
    return count


def _check_name(name: str) -> None:
    if not name.strip() or "#" in name:
        raise ValueError("gate name must be non-blank and must not contain '#'")


def _raise_if_only_hooks(err: ConditionFailedError, own_ops: int) -> None:
    """A condition that only a hook's op failed will not heal by retrying."""
    if all(i >= own_ops for i in err.failed):
        raise err


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _backoff(attempt: int) -> None:
    time.sleep(min(0.001 * (attempt + 1), 0.02))
