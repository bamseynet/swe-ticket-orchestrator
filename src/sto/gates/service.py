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

Quorum and veto (D3-06) are the close path of ``decide``. A :class:`DecisionPolicy` supplies the
gate's quorum (a list of ``(role, count)``), each person's roles and any separation-of-duties
refusals. A service without a policy refuses every decision (:class:`PolicyMissingError`), so a
missed builder fails closed instead of dropping separation of duties (D3-25). Production code gets
its service from ``gates.policy.build_gate_service``; the v0 single-approver gate (one approval
from anyone) exists only as ``GateService.unpoliced_for_tests``.

* The quorum is read when the gate opens and frozen beside it (``QUO#name#round``). Duplicate
  roles, a count below 1 or a blank role are refused then (:class:`QuorumConfigError`), so one
  role cannot count twice. The ``Gate`` record itself is unchanged.
* One person (the actor string) has one vote per gate round, whatever the surface. A sub-quorum
  approval commits a vote record (``VOTE#name#round#<hash of actor>``) and an audit entry and
  leaves the gate open. A person holding several roles fills one slot; slots are assigned by
  matching, so the order of votes does not matter.
* A vote counts only while its subject digest is the gate's current one (a moved subject drops
  earlier votes; the person may vote again) and while its voter is still eligible at the close.
* Any negative decision closes the gate whatever the votes, is exempt from the digest match and
  from the quorum roles (not from the policy's refusals), and needs a comment. An approval
  needs none.
* All decisions of a run serialise on the audit chain head (``RUN#r/CHAIN``, see ``AuditWriter``),
  and a vote also ``Check``s the gate's version, so a vote cannot slip in beside a close.
* Hooks run when a decision closes the gate, not for a vote that leaves it open.
* A lost race waits a random time before the next read (``retry.Backoff``: full jitter, injected
  sleep and RNG), so N concurrent approvals of an N-quorum gate all commit (D3-17). A write whose
  answer was lost (``TransactionOutcomeUnknownError``) is reconciled by re-reading, never retried
  blind: if our decision landed it is returned, not refused as a duplicate or a closed gate.
* A pre-decision guard (D3-26) runs inside every approval attempt, vote or close, on the attempt's
  fresh reads, after the policy refusals and before the count. It may raise to refuse and returns
  ``Check`` ops that join the same transaction, so a fact it read cannot change between the read
  and the write (``gates.moving`` pins ``MOVE#state`` this way). A negative decision runs no
  guard: a veto is never delayed. A condition that fails on a guard's op is retried like a lost
  race, so the guard runs again on fresh reads (and then refuses, if it now should).
* Exhausted retries raise :class:`GateContentionError` (transient), never the store's
  ``ConditionFailedError``.

Rounds of one gate are ordered: a new round opens only after every lower round is closed, a
round with a newer sibling can no longer be decided, and a non-approved close voids only
*earlier* approved rounds (ADR-0005 #8). The number of rounds per gate is capped so that voiding
them all always fits in one transaction (ADR-0017: 100 operations).
"""

from __future__ import annotations

import copy
import hashlib
import time
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

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
    TransientError,
    from_wire,
    to_wire,
)
from sto.engine.commands import OpenGate
from sto.gates.carry_over import Citation
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
from sto.gates.retry import Backoff
from sto.store.ports import (
    AUDIT,
    MAX_TRANSACTION_OPS,
    Absent,
    Check,
    Condition,
    ConditionFailedError,
    Item,
    Key,
    Op,
    Put,
    Scope,
    Store,
    TeamScope,
    TransactionConflictError,
    TransactionOutcomeUnknownError,
    VersionIs,
    require_scope,
)

# A close writes gate, decision, outbox and audit (5 ops with the chain head) plus one per earlier
# approved round. Rounds are capped so that worst case is 5 + 89 and leaves room for hooks.
MAX_ROUNDS_PER_GATE = 90
SYSTEM_ACTOR = "system"
# The engine's service identity (``issuer|subject``). Only ``close_carried`` may close a gate as
# it; ``decide`` refuses it, and a service approval is honoured only with a citation (D2-31).
CARRY_ACTOR = "sto-engine|carry-over"

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


class StaleRoundError(GateError):
    """A newer round of this gate exists, so this round can no longer be decided."""

    code = "stale_round"


class CommentRequiredError(GateError):
    """A request for changes, a reject or a retest without a (non-blank) comment."""

    code = "comment_required"


class DuplicateVoteError(GateError):
    """This person already has a vote for the current subject of the gate round."""

    code = "already_voted"


class QuorumConfigError(GateError):
    """A quorum that cannot be enforced: a repeated or blank role, or a count below 1."""

    code = "quorum_invalid"


class PolicyMissingError(GateError):
    """The service has no :class:`DecisionPolicy`, so it cannot tell who may decide. Refused."""

    code = "policy_missing"


class CarryStaleError(GateError):
    """409 ``carry_stale``: a carried close found the gate closed, moved, or something new written
    since the engine read. Nothing was written; the gate stays open for a person."""

    code = "carry_stale"


class GateContentionError(TransientError):
    """The gate kept changing under this call (or the store kept conflicting) until the retries
    ran out. Nothing was written. Retry the call."""

    code = "gate_contention"


class GateRoundLimitError(GateError):
    """Too many rounds, or a transaction that would pass the store's operation cap."""

    code = "gate_round_limit"


class GateConflictError(GateError):
    """``open_gate`` for a triple that already holds a different gate (a bug, not a replay)."""

    code = "gate_conflict"


def gate_key(run_id: RunId, name: str, round: int) -> Key:
    return Key(run_pk(run_id), f"GATE#{name}#{round}")


@dataclass(frozen=True)
class QuorumRule:
    """``count`` distinct people holding ``role``. Anything with ``role`` and ``count`` (the config
    schema's ``Quorum``) is accepted where a rule is expected."""

    role: str
    count: int


@dataclass(frozen=True)
class GuardContext:
    """What a pre-decision guard sees: the open gate as read for this attempt, the decision kind
    and who decides. ``reader`` is read-only."""

    reader: ReadOnly
    scope: Scope
    gate: Gate
    kind: DecisionKind
    actor: str


# Raise a ``StoError`` to refuse; return ops (``Check``) for the decide transaction. It may run
# several times for one call, on fresh reads each time, so it must have no side effects.
DecisionGuard = Callable[[GuardContext], Sequence[Op]]


class DecisionPolicy(Protocol):
    """What the service cannot know itself: the gate's quorum, who holds which role, and who is
    barred (separation of duties, D3-05). It is read at each attempt and must not write."""

    def quorum(self, scope: Scope, gate: Gate) -> Sequence[QuorumRule]:
        """Read once, when the gate opens. Empty means one approval from any eligible person."""
        ...

    def roles(self, scope: Scope, gate: Gate, actor: str) -> Collection[str]:
        """The roles ``actor`` can vote in on this gate."""
        ...

    def refusals(self, scope: Scope, gate: Gate, actor: str, *, negative: bool) -> Sequence[str]:
        """Reasons ``actor`` may not decide now; empty means eligible."""
        ...


@dataclass(frozen=True)
class Decided:
    """``gate`` is the gate as left by this decision: still open for a vote below quorum."""

    gate: Gate
    decision: Decision

    @property
    def closed(self) -> bool:
        return not self.gate.is_open


class GateService:
    def __init__(
        self,
        store: Store,
        *,
        hooks: GateHooks | None = None,
        audit: AuditWriter | None = None,
        policy: DecisionPolicy | None = None,
        retry: Backoff | None = None,
        guards: Sequence[DecisionGuard] = (),
    ) -> None:
        self._guards = tuple(guards)
        self._policy = policy
        self._unpoliced = False
        self._retry = retry if retry is not None else Backoff()
        self._store = store
        self._reader = ReadOnly(store)
        self._hooks = hooks if hooks is not None else GateHooks()
        self._audit: AuditWriter = audit if audit is not None else ChainedAuditWriter()

    @classmethod
    def unpoliced_for_tests(cls, store: Store, **kwargs: Any) -> GateService:
        """The v0 single-approver gate: no policy, so one approval from anyone closes a gate.
        For tests only; production code must use ``gates.policy.build_gate_service``."""
        service = cls(store, **kwargs)
        service._unpoliced = True
        return service

    def with_guards(self, *guards: DecisionGuard) -> GateService:
        """A service with the same store, hooks, audit, policy and retry and these guards added.
        The shared builder's service gets the moving-subject guard this way (D3-26)."""
        other = copy.copy(self)
        other._guards = (*self._guards, *guards)
        return other

    # --- open -------------------------------------------------------------------------------

    def open_gate(self, scope: Scope, cmd: OpenGate) -> Gate:
        require_scope(scope)
        _check_name(cmd.name)
        key = gate_key(cmd.run_id, cmd.name, cmd.round)
        last: Exception | None = None
        hook_failures = 0
        for attempt in range(self._retry.attempts):
            existing = self._store.get(scope, key)
            if existing is not None:
                gate = from_wire(Gate, existing.data)
                if gate.subject != cmd.subject or gate.type != cmd.type:
                    raise GateConflictError(
                        f"gate {cmd.name!r} round {cmd.round} already exists with another subject"
                    )
                return gate
            siblings = self._rounds(scope, cmd.run_id, cmd.name)
            if any(other.round > cmd.round for _, other in siblings):
                raise GateConflictError(
                    f"cannot open round {cmd.round} of gate {cmd.name!r}: a newer round exists"
                )
            if len(siblings) >= MAX_ROUNDS_PER_GATE:
                raise GateRoundLimitError(
                    f"gate {cmd.name!r} already has {len(siblings)} rounds; "
                    f"the limit is {MAX_ROUNDS_PER_GATE} rounds"
                )
            for _, other in siblings:
                if other.round < cmd.round and other.is_open:
                    raise GateConflictError(
                        f"cannot open round {cmd.round} of gate {cmd.name!r}: "
                        f"round {other.round} is still open"
                    )
            gate = Gate(GateId.new(), cmd.run_id, cmd.name, cmd.type, cmd.round, cmd.subject)
            rules = _checked_quorum(self._policy.quorum(scope, gate) if self._policy else ())
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
            if rules:
                own.append(Put(_quorum_key(gate), {"rules": rules}, Absent()))
            hook_ops = self._hooks.open_ops(OpenContext(self._reader, scope, gate))
            ops = _within_cap([*own, *hook_ops])
            try:
                self._store.transact(scope, ops)
            except ConditionFailedError as err:
                hook_failures = _count_hook_failure(err, len(own), hook_failures)
                last = err
                self._retry.wait(attempt)
            except TransactionConflictError as err:
                last = err
                self._retry.wait(attempt)
            else:
                return gate
        raise GateContentionError(
            f"gate {cmd.name!r} round {cmd.round} kept changing; try again"
        ) from last

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
        if kind is not DecisionKind.APPROVE and not comment.strip():
            raise CommentRequiredError(f"a {kind.value} decision needs a comment")
        if actor == CARRY_ACTOR:
            raise DecisionNotAllowedError("the engine's service identity cannot decide a gate")
        key = gate_key(run_id, gate, round)
        decision_id = DecisionId.new()
        last: Exception | None = None
        hook_failures = 0
        for attempt in range(self._retry.attempts):
            item = self._store.get(scope, key)
            if item is None:
                raise GateNotFoundError(f"no gate {gate!r} round {round} for run {run_id}")
            current = from_wire(Gate, item.data)
            if isinstance(last, TransactionOutcomeUnknownError):
                # The last write's answer was lost and it may have landed since (even after the
                # previous attempt's read): our own decision id proves it, so return it rather
                # than refuse the person's own vote as a duplicate or a closed gate.
                landed = self._landed(scope, current, actor, kind, decision_id)
                if landed is not None:
                    return Decided(current, landed)
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
            if any(g.round > round for _, g in self._rounds(scope, run_id, gate)):
                raise StaleRoundError(
                    f"gate {gate!r} round {round} was superseded by a newer round"
                )
            self._refuse_if_barred(scope, current, actor, kind)
            guard_ops = self._guard_ops(scope, current, actor, kind)
            counted = [decision.id]
            if kind is DecisionKind.APPROVE:
                # A vote's count is only as fresh as the chain head the audit entry will be
                # conditioned on. Read the head BEFORE counting and compare it after the audit ops
                # are built (they read it again): equal means no decision committed in between, so
                # the count is the count this transaction commits against. Heads only move
                # forward. A close needs no such check: it already counted a quorum, anything that
                # lands in between is a veto or another close, and both move the gate's version.
                head = self._head_version(scope, run_id)
                tally = self._tally(scope, current, decision)
                if not tally.closes:
                    own = self._vote_ops(scope, item, current, decision, tally)
                    if self._head_version(scope, run_id) != head:
                        self._retry.wait(attempt)
                        continue  # a decision committed while we counted: count again
                    try:
                        self._store.transact(scope, _within_cap([*own, *guard_ops]))
                    except ConditionFailedError as err:
                        last = err  # a close or a vote raced us: re-read and count again
                        self._retry.wait(attempt)
                    except TransactionConflictError as err:
                        last = err
                        self._retry.wait(attempt)
                    else:
                        return Decided(current, decision)
                    continue
                counted = tally.counted
            closed = current.advance(_CLOSES_AS[kind], closed_by=actor)
            invalidated = self._earlier_approvals(scope, current, kind)
            own = self._close_ops(scope, item, closed, decision, invalidated, counted)
            # The audit chain head was read inside _close_ops. Confirm the set of approvals to
            # void is still the same now: any later change to a round also moves the head.
            if [g.round for _, g in self._earlier_approvals(scope, current, kind)] != [
                g.round for _, g in invalidated
            ]:
                self._retry.wait(attempt)
                continue
            hook_ops = self._hooks.decide_ops(
                DecideContext(self._reader, scope, current, closed, decision)
            )
            ops = _within_cap([*own, *guard_ops, *hook_ops])
            try:
                self._store.transact(scope, ops)
            except ConditionFailedError as err:
                # a guard's check retries like our own; a hook's gets a few fresh reads
                hook_failures = _count_hook_failure(err, len(own) + len(guard_ops), hook_failures)
                last = err  # re-read: closed now -> gate_closed above; still open -> try again
                self._retry.wait(attempt)
            except TransactionConflictError as err:
                last = err
                self._retry.wait(attempt)
            else:
                return Decided(closed, decision)
        raise GateContentionError(f"gate {gate!r} round {round} kept changing; try again") from last

    # --- carried close (D2-31) --------------------------------------------------------------

    def close_carried(
        self,
        scope: Scope,
        *,
        gate: Gate,
        citation: Citation,
        chain: int | None = None,
        extra: Sequence[Op] = (),
    ) -> Decided:
        """Close ``gate`` APPROVED by carry-over, as the engine's service identity.

        ``gate`` is the open gate as the engine read it. The close is one conditional transaction:
        the gate is still open, unchanged and on the same subject; ``chain`` (the audit chain head
        version the engine read before deciding, ``None`` for an absent head) is still current, so
        nothing was opened or decided on the run since; the pre-decision guards (a closed ticket)
        run as for a person; and ``extra`` ops the engine read (the head log, the round record)
        join it. The citation is written as ``CITE#name#round`` and into the audit entry. Any
        failed condition is :class:`CarryStaleError` with nothing written: no retry, because the
        engine must decide again on fresh facts."""
        require_scope(scope)
        if citation.gate_id.__class__ is not GateId or citation.patch_id != gate.subject.patch_id:
            raise CarryStaleError("the citation does not name this gate's patch")
        key = gate_key(gate.run_id, gate.name, gate.round)
        item = self._store.get(scope, key)
        if item is None:
            raise GateNotFoundError(f"no gate {gate.name!r} round {gate.round}")
        current = from_wire(Gate, item.data)
        if not current.is_open or current != gate:
            raise CarryStaleError(f"gate {gate.name!r} round {gate.round} is not open as read")
        if any(g.round > gate.round for _, g in self._rounds(scope, gate.run_id, gate.name)):
            raise CarryStaleError(f"gate {gate.name!r} round {gate.round} has a newer round")
        if chain is not None and self._head_version(scope, gate.run_id) != chain:
            raise CarryStaleError("something was written to the run since the carry-over read")
        decision = Decision(
            DecisionId.new(),
            current.id,
            current.round,
            CARRY_ACTOR,
            Surface.UI,  # no engine surface exists; the actor and CITE# identify the origin
            DecisionKind.APPROVE,
            current.subject.digest(),
            f"carried from round {citation.origin_round} (patch {citation.patch_id})",
        )
        wire = _citation_wire(citation)
        closed = current.advance(GateStatus.APPROVED, closed_by=CARRY_ACTOR)
        own = self._close_ops(
            scope, item, closed, decision, [], [decision.id], audit_extra={"citation": wire}
        )
        guard_ops = self._guard_ops(scope, current, CARRY_ACTOR, DecisionKind.APPROVE)
        cite = Put(
            cite_key(current),
            {**wire, "decision_id": str(decision.id), "closed_gate_id": str(current.id)},
            Absent(),
        )
        # The audit ops above are conditioned on the chain head they read. Heads only move
        # forward, so equal to the engine's read now means equal when they read it: nothing was
        # opened or decided on the run since.
        if chain is not None and self._head_version(scope, gate.run_id) != chain:
            raise CarryStaleError("something was written to the run since the carry-over read")
        try:
            self._store.transact(scope, _within_cap([*own, cite, *guard_ops, *extra]))
        except (ConditionFailedError, TransactionConflictError) as err:
            raise CarryStaleError("the gate or the run changed during the carried close") from err
        return Decided(closed, decision)

    # --- internals --------------------------------------------------------------------------

    # --- quorum -----------------------------------------------------------------------------

    def _refuse_if_barred(self, scope: Scope, gate: Gate, actor: str, kind: DecisionKind) -> None:
        if self._policy is None:
            if self._unpoliced:
                return
            raise PolicyMissingError(
                f"gate {gate.name!r} round {gate.round} cannot be decided: no decision policy"
            )
        reasons = self._policy.refusals(scope, gate, actor, negative=kind.is_negative)
        if reasons:
            raise DecisionNotAllowedError(
                f"{actor} may not {kind.value} gate {gate.name!r} round {gate.round}: "
                + ", ".join(reasons)
            )

    def _guard_ops(self, scope: Scope, gate: Gate, actor: str, kind: DecisionKind) -> list[Op]:
        """Run the guards on this attempt's reads; a veto runs none."""
        if kind.is_negative:
            return []
        ctx = GuardContext(self._reader, scope, gate, kind, actor)
        return [op for guard in self._guards for op in guard(ctx)]

    def _landed(
        self, scope: Scope, gate: Gate, actor: str, kind: DecisionKind, decision_id: DecisionId
    ) -> Decision | None:
        """The decision with this id if it was committed: a close writes ``DEC#...#id``, a vote
        writes the voter's ``VOTE#`` record. Another id (an older vote by the same person) is not
        ours."""
        closed = self._store.get(scope, _decision_key(gate, decision_id))
        if closed is not None:
            return from_wire(Decision, closed.data)
        if kind is DecisionKind.APPROVE:
            vote = self._store.get(scope, _vote_key(gate, actor))
            if vote is not None:
                found = from_wire(Decision, vote.data["decision"])
                if found.id == decision_id:
                    return found
        return None

    def audit_version(self, scope: Scope, run_id: RunId) -> int | None:
        """The version of the run's audit chain head, as the service's audit writer moves it on
        every open and decision. Callers (the carry-over engine) condition on it through
        ``close_carried(chain=...)`` and never touch the chain themselves."""
        return self._head_version(scope, run_id)

    def _head_version(self, scope: Scope, run_id: RunId) -> int | None:
        head = self._store.get(scope, Key(run_pk(run_id), CHAIN_SK))
        return None if head is None else head.version

    def _rules(self, scope: Scope, gate: Gate) -> list[QuorumRule]:
        item = self._store.get(scope, _quorum_key(gate))
        if item is None:
            return []  # opened without a quorum: one approval from any eligible person
        return [QuorumRule(r["role"], r["count"]) for r in item.data["rules"]]

    def _votes(self, scope: Scope, gate: Gate) -> list[tuple[Item, Decision]]:
        found: list[tuple[Item, Decision]] = []
        cursor: str | None = None
        while True:
            page = self._store.query(
                scope, run_pk(gate.run_id), sk_prefix=_vote_prefix(gate), cursor=cursor
            )
            found += [(i, from_wire(Decision, i.data["decision"])) for i in page.items]
            cursor = page.cursor
            if cursor is None:
                return found

    def _tally(self, scope: Scope, gate: Gate, decision: Decision) -> _Tally:
        """Count this approval with the earlier votes that still stand: bound to the gate's
        current subject, by a person who is still eligible (PLAN 4.1). Nothing is written."""
        rules = self._rules(scope, gate)
        if not rules:
            return _Tally(True, [decision.id], None, None)
        policy = self._policy
        if policy is None:
            raise QuorumConfigError("the gate has a quorum but the service has no policy")
        digest, actor = gate.subject.digest(), decision.actor
        stale: Item | None = None
        voters: list[tuple[str, frozenset[str]]] = []
        counted: list[DecisionId] = []
        for vote_item, vote in self._votes(scope, gate):
            if vote.actor == actor:
                if vote.subject_digest == digest:
                    raise DuplicateVoteError(
                        f"{actor} already approved gate {gate.name!r} round {gate.round}"
                    )
                stale = vote_item  # a vote for a subject that moved: replaced, never counted
            elif vote.subject_digest == digest and not policy.refusals(
                scope, gate, vote.actor, negative=False
            ):
                voters.append((vote.actor, frozenset(policy.roles(scope, gate, vote.actor))))
                counted.append(vote.id)
        wanted = {r.role for r in rules}
        mine = frozenset(policy.roles(scope, gate, actor)) & wanted
        if not mine:
            raise DecisionNotAllowedError(
                f"{actor} holds none of the roles gate {gate.name!r} needs: {sorted(wanted)}"
            )
        voters.append((actor, mine))
        slots = [r.role for r in rules for _ in range(r.count)]
        met = _fills(slots, [roles for _, roles in voters])
        return _Tally(met, [*counted, decision.id], stale, len(voters))

    def _vote_ops(
        self, scope: Scope, item: Item, gate: Gate, decision: Decision, tally: _Tally
    ) -> list[Op]:
        when: Condition = Absent() if tally.stale is None else VersionIs(tally.stale.version)
        entry = AuditEntry(
            gate.run_id,
            "gate.voted",
            decision.actor,
            {
                "gate": gate.name,
                "round": gate.round,
                "gate_id": str(gate.id),
                "decision": decision.kind.value,
                "decision_id": str(decision.id),
                "surface": decision.surface.value,
                "subject_digest": decision.subject_digest,
                "comment": decision.comment,
                "votes": tally.votes,
            },
            _now_ms(),
        )
        return [
            # The vote is only valid while the gate is still the one that was read.
            Check(item.key, VersionIs(item.version)),
            Put(
                _vote_key(gate, decision.actor),
                {"actor": decision.actor, "decision": to_wire(decision)},
                when,
            ),
            *self._audit.ops(self._reader, scope, entry),
        ]

    def _rounds(self, scope: Scope, run_id: RunId, name: str) -> list[tuple[Item, Gate]]:
        page = self._store.query(scope, run_pk(run_id), sk_prefix=f"GATE#{name}#")
        gates = [(item, from_wire(Gate, item.data)) for item in page.items]
        return [(item, g) for item, g in gates if g.name == name]  # "qa" is not "qa#2"'s prefix

    def _earlier_approvals(
        self, scope: Scope, closing: Gate, kind: DecisionKind
    ) -> list[tuple[Item, Gate]]:
        """Approved EARLIER rounds of the same gate that this close voids (rule 3). An approval
        voids nothing."""
        if kind is DecisionKind.APPROVE:
            return []
        return [
            (item, g)
            for item, g in self._rounds(scope, closing.run_id, closing.name)
            if g.round < closing.round and g.status is GateStatus.APPROVED
        ]

    def _close_ops(
        self,
        scope: Scope,
        item: Item,
        closed: Gate,
        decision: Decision,
        invalidated: list[tuple[Item, Gate]],
        counted: list[DecisionId],
        audit_extra: dict[str, Any] | None = None,
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
            "decision_ids": [str(d) for d in counted],
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
                "surface": decision.surface.value,
                "status": closed.status.value,
                "subject_digest": decision.subject_digest,
                "comment": decision.comment,
                "decision_ids": [str(d) for d in counted],
                "invalidated_rounds": [g.round for _, g in invalidated],
                **(audit_extra or {}),
            },
            _now_ms(),
        )
        ops: list[Op] = [
            # The single close: succeeds only if nobody wrote this gate since it was read.
            Put(item.key, to_wire(closed), VersionIs(item.version)),
            Put(_decision_key(closed, decision.id), to_wire(decision), Absent()),
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


@dataclass(frozen=True)
class _Tally:
    closes: bool
    # the approvals that stand: earlier votes in the store's order of VOTE# keys (a hash of the
    # voter, so NOT time order), then this decision last. Consumers must not read order as time.
    counted: list[DecisionId]
    stale: Item | None  # this person's earlier vote for a subject that has moved
    votes: int | None  # people who now hold a vote, this one included


def _decision_key(gate: Gate, decision_id: DecisionId) -> Key:
    return Key(run_pk(gate.run_id), f"DEC#{gate.name}#{gate.round}#{decision_id}")


def cite_key(gate: Gate) -> Key:
    """Where a carried close's citation lives (``CITE#name#round``): guard 2 honours a service
    approval only when this record names the gate."""
    return Key(run_pk(gate.run_id), f"CITE#{gate.name}#{gate.round}")


def _citation_wire(c: Citation) -> dict[str, Any]:
    return {
        "gate_id": str(c.gate_id),
        "round": c.round,
        "origin_gate_id": str(c.origin_gate_id),
        "origin_round": c.origin_round,
        "patch_id": c.patch_id,
        "approvers": list(c.approvers),
    }


def _quorum_key(gate: Gate) -> Key:
    return Key(run_pk(gate.run_id), f"QUO#{gate.name}#{gate.round}")


def _vote_prefix(gate: Gate) -> str:
    return f"VOTE#{gate.name}#{gate.round}#"


def _vote_key(gate: Gate, actor: str) -> Key:
    # hashed: an actor is ``issuer|subject`` and may hold characters a sort key should not
    return Key(run_pk(gate.run_id), _vote_prefix(gate) + hashlib.sha256(actor.encode()).hexdigest())


def _checked_quorum(rules: Sequence[QuorumRule]) -> list[dict[str, object]]:
    """The wire form of a quorum, or :class:`QuorumConfigError`: one entry per role, a real role
    name and a count of at least 1, so a role cannot count twice."""
    out: list[dict[str, object]] = []
    seen: set[str] = set()
    for rule in rules:
        role, count = rule.role, rule.count
        if not isinstance(role, str) or not role.strip():
            raise QuorumConfigError("a quorum role must be a non-blank name")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise QuorumConfigError(f"quorum role {role!r} needs a count of at least 1")
        if role in seen:
            raise QuorumConfigError(f"quorum role {role!r} is listed twice")
        seen.add(role)
        out.append({"role": role, "count": count})
    return out


def _fills(slots: list[str], voters: list[frozenset[str]]) -> bool:
    """True if every slot (a role, once per head needed) can get its own voter holding that role.
    Augmenting-path matching, so a voter with two roles takes whichever one is left."""
    owner: dict[int, int] = {}  # voter -> slot

    def place(slot: int, seen: set[int]) -> bool:
        for v, roles in enumerate(voters):
            if slots[slot] in roles and v not in seen:
                seen.add(v)
                if v not in owner or place(owner[v], seen):
                    owner[v] = slot
                    return True
        return False

    return all(place(s, set()) for s in range(len(slots)))


def verify_audit_chain(store: Store | ReadOnly, scope: Scope, run_id: RunId) -> int:
    """Walk a run's audit table and check sequence, links and hashes against the chain head.
    Returns the number of entries; raises ``ValueError`` on the first break."""
    prev, count = GENESIS_HASH, 0
    for item in store.query(scope, audit_pk(run_id), table=AUDIT).items:
        body = {k: v for k, v in item.data.items() if k != "hash"}
        count += 1
        team = scope.team if isinstance(scope, TeamScope) else ""
        if body.get("run") != str(run_id) or body.get("team") != team:
            raise ValueError(f"audit chain broken at entry {count}: wrong run or team")
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


def _within_cap(ops: list[Op]) -> list[Op]:
    if len(ops) > MAX_TRANSACTION_OPS:
        raise GateRoundLimitError(
            f"the change needs {len(ops)} operations; the store takes {MAX_TRANSACTION_OPS}"
        )
    return ops


def _check_name(name: str) -> None:
    if not name.strip() or "#" in name:
        raise ValueError("gate name must be non-blank and must not contain '#'")


HOOK_RETRIES = 3  # fresh reads given to a condition that only a hook's op failed


def _count_hook_failure(err: ConditionFailedError, own_ops: int, seen: int) -> int:
    """How many attempts have failed only on a hook's op, counting this one. A hook's check can
    fail because what it read moved (``refuse_closed_ticket`` pinning ``MOVE#state``), and the
    next attempt reads again, so a few such failures are retried; the hook then raises its own
    refusal. A hook condition that never holds is re-raised after ``HOOK_RETRIES`` tries, not after
    the whole retry bound."""
    if not all(i >= own_ops for i in err.failed):
        return seen
    if seen >= HOOK_RETRIES:
        raise err
    return seen + 1


def _now_ms() -> int:
    return time.time_ns() // 1_000_000
