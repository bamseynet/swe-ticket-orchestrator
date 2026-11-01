"""Effects v0 (D1-07): plan, claim, write, settle (PLAN 6.3, 4.3 rules 1, 2 and 5, ADR-0011).

The claim is one transaction. It writes the effect as ``ATTEMPTING`` (with a lease) at the
version it read, and holds ``Check``s on everything the decision rested on: the run, the audit
chain head, every required gate and the round after it, and the team and fleet switches. A Stop,
a gate open or decision, or a switch flip commits a new version, so it and the claim cannot both
win; whichever loses re-reads. Only ``scoped`` and ``gated`` effects exist in v0.

Status comes only from a receipt: ``CONFIRMED`` needs one with read-back. Every status change is
saved at the version it was decided on, so a late or slow caller can never overwrite a newer
state. An attempt of unknown outcome is never voided and never retried past ``max_attempts``: it
goes to ``blocked`` (ADR-0011: ambiguity is BLOCKED, not a guess).
"""

from __future__ import annotations

import dataclasses
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sto.adapters.ports import RefusedError, StaleHeadError
from sto.domain import (
    Decision,
    DecisionId,
    DecisionKind,
    Effect,
    EffectClass,
    EffectId,
    EffectStatus,
    Gate,
    GateStatus,
    Run,
    RunId,
    RunStatus,
    Subject,
    effect_key,
    from_wire,
    to_wire,
)
from sto.domain.errors import PermanentError, TransientError
from sto.store.ports import (
    PLATFORM,
    Absent,
    Check,
    Condition,
    ConditionFailedError,
    Item,
    Op,
    Put,
    Scope,
    Store,
    TeamScope,
    TransactionConflictError,
    VersionIs,
)

from .ports import (
    FLEET_SWITCHES,
    IMPLICIT_TYPES,
    STALE_EDGE_TYPES,
    TEAM_SWITCHES,
    EffectHandler,
    Failed,
    Outcome,
    Pending,
    Voided,
    Written,
    chain_key,
    decision_prefix,
    effect_item_key,
    gate_key,
    gate_prefix,
    run_key,
    run_pk,
    switch_field,
    switches_for,
)

_ACTIVE = frozenset({RunStatus.RUNNING, RunStatus.WAITING_EXTERNAL})
# A run in one of these will never act again, so its unwritten *gated* effects are voided. Any
# other inactive run (waiting, blocked, queued) only holds them: it may come back.
_DEAD = frozenset(
    {RunStatus.CANCELLING, RunStatus.CANCELLED, RunStatus.DONE, RunStatus.REJECTED}
    | {RunStatus.CLOSED, RunStatus.EXPIRED}
)
_APPROVING = frozenset({DecisionKind.APPROVE, DecisionKind.WAIVE})
_TRIES = 8
_CARRIED = ("subject", "floor")  # envelope fields that outlive every state change
# The lease. A worker that is slow but alive can lose its lease and still write: a second worker
# takes over and calls the writer with the same key (reproduced: writer calls [A, B]). The fence
# keeps the *records* right, but not the outside world, so external writes rely on the adapter
# deduplicating on the idempotency key, and the lease must be longer than any adapter timeout.
# Real adapters must look up before they create (PLAN 6.3).
DEFAULT_LEASE_SECONDS = 60.0


@dataclass(frozen=True)
class ExecResult:
    """``effect`` is the stored record after the call. ``edge`` is the workflow edge it took
    (``done``, ``stale``, ``conflict``), if any, and is the same on every later replay.
    ``reason`` says why nothing was written, or why it failed: ``gate_invalid``,
    ``run_not_active``, ``held``, ``in_flight``, ``lease_lost``, ``unconfirmed``, a failure name.
    ``blocked`` means the outcome is unknown and a person must decide (ADR-0011)."""

    effect: Effect
    edge: str | None = None
    reason: str | None = None
    blocked: bool = False


@dataclass(frozen=True)
class StopReport:
    """What Stop found: effects it voided, and effects that were tried (ATTEMPTING, RETRYING,
    ACCEPTED), which may have landed and need reconciling (PLAN 14.3)."""

    voided: tuple[Effect, ...] = ()
    in_flight: tuple[Effect, ...] = ()


@dataclass(frozen=True)
class _Rec:
    effect: Effect
    version: int
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _Retry:
    reason: str


@dataclass
class _Claim:
    ops: list[Op] = field(default_factory=list)
    decisions: tuple[DecisionId, ...] = ()


def set_switch(store: Store, scope: TeamScope, name: str, on: bool, *, fleet: bool = False) -> None:
    """Set a switch, conditional on the item's version, so a concurrent change is never lost."""
    where, key = (PLATFORM, FLEET_SWITCHES) if fleet else (scope, TEAM_SWITCHES)
    for _ in range(_TRIES):
        item = store.get(where, key)
        data = dict(item.data) if item else {}
        data[switch_field(name)] = on
        when: Condition = Absent() if item is None else VersionIs(item.version)
        try:
            store.put(where, key, data, when=when)
        except ConditionFailedError:
            continue
        return
    raise TransientError(f"switch {name!r} kept changing")


class EffectExecutor:
    def __init__(
        self,
        store: Store,
        scope: TeamScope,
        *,
        max_attempts: int = 3,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._store, self._scope, self._max = store, scope, max_attempts
        self._lease, self._clock = lease_seconds, clock

    # --- records ----------------------------------------------------------------------------

    def _pages(self, scope: Scope, pk: str, prefix: str) -> list[Item]:
        items: list[Item] = []
        cursor: str | None = None
        while True:
            page = self._store.query(scope, pk, sk_prefix=prefix, cursor=cursor)
            items.extend(page.items)
            if page.cursor is None:
                return items
            cursor = page.cursor

    @staticmethod
    def _rec(item: Item) -> _Rec:
        return _Rec(from_wire(Effect, item.data["effect"]), item.version, dict(item.data["meta"]))

    def _load(self, run_id: RunId, idempotency_key: str) -> _Rec:
        item = self._store.get(self._scope, effect_item_key(run_id, idempotency_key))
        if item is None:
            raise KeyError(f"no effect {idempotency_key!r} in run {run_id}")
        return self._rec(item)

    def _all(self, run_id: RunId) -> list[_Rec]:
        return [self._rec(i) for i in self._pages(self._scope, run_pk(run_id), "FX#")]

    def get(self, run_id: RunId, idempotency_key: str) -> Effect:
        return self._load(run_id, idempotency_key).effect

    def _put(self, effect: Effect, meta: dict[str, Any], when: Condition) -> Put:
        key = effect_item_key(effect.run_id, effect.idempotency_key)
        return Put(key, {"effect": to_wire(effect), "meta": meta}, when=when)

    def _save(self, rec: _Rec, effect: Effect, meta: dict[str, Any], *extra: Op) -> None:
        """Save at the version ``rec`` was read at. The planned subject and the retry floor carry
        over every save."""
        carried = {k: rec.meta[k] for k in _CARRIED if k in rec.meta}
        self._store.transact(
            self._scope, [self._put(effect, {**carried, **meta}, VersionIs(rec.version)), *extra]
        )

    @staticmethod
    def _replay(rec: _Rec, reason: str | None = None) -> ExecResult:
        meta = rec.meta
        return ExecResult(
            rec.effect,
            meta.get("edge"),
            reason or meta.get("reason"),
            bool(meta.get("blocked")),
        )

    # --- plan -------------------------------------------------------------------------------

    def plan(
        self,
        run_id: RunId,
        type: str,
        stage: str,
        visit: int,
        klass: EffectClass,
        subject_digest: str,
        *,
        requires_gates: tuple[str, ...] = (),
        key: str | None = None,
        subject: Subject | None = None,
    ) -> Effect:
        """Record a PLANNED effect, or return the one already planned under the same key.
        ``key`` overrides the default 5-tuple key for effects with a narrower scope (PLAN 6.3).
        A gated effect also records the ``subject`` it was planned for (the ``RunEffect`` carries
        it), whose digest must be ``subject_digest``: after a merge its head is compared with the
        merged one."""
        if klass not in (EffectClass.SCOPED, EffectClass.GATED):
            raise ValueError("v0 plans scoped or gated effects only")
        if klass is EffectClass.GATED and subject is None:
            raise ValueError("a gated effect needs the subject it was planned for")
        if subject is not None and subject.digest() != subject_digest:
            raise ValueError("subject_digest is not the digest of the subject")
        meta = {} if subject is None else {"subject": to_wire(subject)}
        effect = Effect(
            id=EffectId.new(),
            run_id=run_id,
            type=type,
            stage=stage,
            visit=visit,
            klass=klass,
            idempotency_key=key or effect_key(run_id, stage, visit, type, subject_digest),
            requires_gates=requires_gates,
            subject_digest=subject_digest,
        )
        try:
            self._store.transact(self._scope, [self._put(effect, meta, Absent())])
        except ConditionFailedError:
            rec = self._load(run_id, effect.idempotency_key)
            existing = rec.effect
            same = (existing.type, existing.klass, existing.subject_digest, existing.requires_gates)
            if same != (type, klass, subject_digest, effect.requires_gates):
                raise ValueError(
                    f"idempotency key {effect.idempotency_key!r} is already used by another effect"
                ) from None
            return existing
        return effect

    # --- execute ----------------------------------------------------------------------------

    def execute(
        self,
        run_id: RunId,
        idempotency_key: str,
        handler: EffectHandler,
        *,
        live: Subject | None = None,
    ) -> ExecResult:
        """Claim and write one effect, then settle it from the outcome.

        ``live`` is the subject as it stands now (head, patch, ticket text). **The caller must read
        it afresh from the ticket and the SCM at this moment, not reuse the command's subject**:
        passing the planned subject makes the check against it vacuous. A gated effect is refused
        unless ``live`` still has the digest it was planned with, and every required gate approved
        that head (PLAN 4.3 rule 2). Once a merge has confirmed, later gated effects compare their
        planned head and their gates with the merged head instead (PLAN 293).

        Safe to call again after ``RETRYING`` or a crash: the same key goes to the writer. A live
        attempt (unexpired lease) is never taken over."""
        token = uuid.uuid4().hex
        for _ in range(_TRIES):
            rec = self._load(run_id, idempotency_key)
            effect = rec.effect
            if effect.status is EffectStatus.ATTEMPTING:
                if self._clock() < float(rec.meta.get("lease_until", 0.0)):
                    return ExecResult(effect, reason="in_flight")
                # The lease lapsed: that worker died or stalled, and may have written.
                self._step(rec, EffectStatus.RETRYING)
                continue
            if effect.status not in (EffectStatus.PLANNED, EffectStatus.RETRYING):
                return self._replay(rec)  # finished, or ACCEPTED and waiting for a poll
            if rec.meta.get("blocked"):
                return self._replay(rec)
            if self._exhausted(rec):
                return self._block(rec, "attempts_exhausted")
            verdict = self._guard(rec, live)
            if isinstance(verdict, str):
                return self._refuse(rec, verdict)
            claimed = effect.advance(
                EffectStatus.ATTEMPTING,
                decision_ids=verdict.decisions if effect.klass is EffectClass.GATED else None,
                subject_digest=effect.subject_digest,
            )
            lease = {"lease_owner": token, "lease_until": self._clock() + self._lease}
            try:
                self._save(rec, claimed, lease, *verdict.ops)
            except (ConditionFailedError, TransactionConflictError):
                continue  # Stop, a decision or a switch won the race: re-read and decide again
            return self._write(run_id, idempotency_key, token, handler)
        raise TransientError(f"effect {idempotency_key!r} kept changing under the claim")

    def _exhausted(self, rec: _Rec) -> bool:
        floor = int(rec.meta.get("floor", 0))
        return (
            rec.effect.status is EffectStatus.RETRYING and rec.effect.attempts - floor >= self._max
        )

    def retry_blocked(self, run_id: RunId, idempotency_key: str) -> Effect:
        """What a person's audited Retry calls (the audit and the caller belong to a later issue):
        clear the block and allow ``max_attempts`` more tries from here. The attempts already made
        stay in the record. The next ``execute`` re-runs every guard."""
        for _ in range(_TRIES):
            rec = self._load(run_id, idempotency_key)
            if not rec.meta.get("blocked"):
                raise ValueError("only a blocked effect can be retried")
            meta = {"floor": rec.effect.attempts, "reason": "retry_requested"}
            try:
                self._store.transact(
                    self._scope,
                    [
                        self._put(
                            rec.effect,
                            {**{k: v for k, v in rec.meta.items() if k in _CARRIED}, **meta},
                            VersionIs(rec.version),
                        )
                    ],
                )
            except (ConditionFailedError, TransactionConflictError):
                continue
            return rec.effect
        raise TransientError(f"effect {idempotency_key!r} kept changing")

    def _step(self, rec: _Rec, target: EffectStatus, **meta: Any) -> None:
        """A bookkeeping move (lease lapsed, void). A lost race re-reads in the caller."""
        try:
            self._save(rec, rec.effect.advance(target), meta)
        except (ConditionFailedError, TransactionConflictError):
            return

    def _block(self, rec: _Rec, reason: str) -> ExecResult:
        meta = {**rec.meta, "blocked": reason, "reason": reason}
        try:
            self._save(rec, rec.effect, meta)
        except ConditionFailedError:
            return self._replay(self._load(rec.effect.run_id, rec.effect.idempotency_key))
        return ExecResult(rec.effect, reason=reason, blocked=True)

    def _refuse(self, rec: _Rec, reason: str) -> ExecResult:
        effect = rec.effect
        if reason == "held":
            return ExecResult(effect, reason="held")
        if effect.attempts > 0:
            # Tried before, so it may have landed: voiding would hide that. A person reconciles.
            return self._block(rec, f"unreconciled:{reason}")
        try:
            voided = effect.advance(EffectStatus.VOIDED)
            self._save(rec, voided, {"reason": reason})
        except ConditionFailedError:  # lost to a cancel or another executor: report what is there
            return self._replay(self._load(effect.run_id, effect.idempotency_key), reason)
        return ExecResult(voided, reason=reason)

    # --- the claim's guard ------------------------------------------------------------------

    def _guard(self, rec: _Rec, live: Subject | None) -> _Claim | str:
        """Read what the claim depends on. Returns the claim's ``Check``s, or a refusal reason:
        ``run_not_active`` and ``gate_invalid`` void the effect, ``held`` leaves it as it is."""
        effect = rec.effect
        gated = effect.klass is EffectClass.GATED
        claim = _Claim()
        run_item = self._store.get(self._scope, run_key(effect.run_id))
        if run_item is None:
            return "run_not_active"
        if gated or effect.type not in IMPLICIT_TYPES:
            # Gated and declared scoped effects need a live run. Only the engine-implicit ones
            # (``IMPLICIT_TYPES``) run on a stopped run: the revert PR after Stop, ``pr.close``.
            status = from_wire(Run, run_item.data).status
            if status in _DEAD:
                return "run_not_active"
            if status not in _ACTIVE:
                return "held"
            claim.ops.append(Check(run_key(effect.run_id), VersionIs(run_item.version)))
        held = self._switches(effect.type, claim.ops)
        if held:
            return "held"
        if gated:
            approved = self._approval(rec, live, claim.ops)
            if isinstance(approved, str):
                return approved
            claim.decisions = approved
        return claim

    def _switches(self, effect_type: str, ops: list[Op]) -> bool:
        """True if a switch is off. Absent is not off; present is on only if exactly ``True``."""
        names = [switch_field(n) for n in switches_for(effect_type)]
        for scope, key in ((self._scope, TEAM_SWITCHES), (PLATFORM, FLEET_SWITCHES)):
            item = self._store.get(scope, key)
            if item is None:
                ops.append(Check(key, Absent(), None if scope is self._scope else PLATFORM))
                continue
            if any(n in item.data and item.data[n] is not True for n in names):
                return True
            ops.append(
                Check(key, VersionIs(item.version), None if scope is self._scope else PLATFORM)
            )
        return False

    def _approval(
        self, rec: _Rec, live: Subject | None, ops: list[Op]
    ) -> tuple[DecisionId, ...] | str:
        """PLAN 4.3.2 and 6.4 guard 2: the latest instance of every required gate is approved at
        the head being merged, by an approving decision bound to that gate's own subject digest.
        Only the head is compared across gates (they see different evidence, and a ticket edit
        between two gates is shown to the next one, PLAN 272); ticket text is covered by the live
        digest before a merge."""
        effect = rec.effect
        frozen = self._frozen_subject(effect.run_id)
        if frozen is not None:
            planned = from_wire(Subject, rec.meta["subject"])
            if planned.head_sha != frozen.head_sha:
                return "gate_invalid"  # planned for other code than the one that was merged
            reference = frozen
        elif live is None:
            raise ValueError("a gated effect needs the live subject")
        elif live.digest() != effect.subject_digest:
            return "gate_invalid"  # the subject moved since it was approved (ticket edit, ...)
        else:
            reference = live
        pk, found = run_pk(effect.run_id), []
        # REQUIREMENT ON THE AuditWriter PORT (src/sto/gates/hooks.py): every AuditWriter must move
        # ``RUN#r/CHAIN`` in the same transaction as the gate open or decision it records. This
        # claim relies on that to notice a gate round that skips numbers (``GATE#g#3`` after an
        # approved round 1), which no per-key check can see. The next-round ``Absent`` check below
        # covers only the immediate successor. Later audit work (D3) must keep this property, or
        # supply another version the gate service bumps on every open and decision.
        chain = self._store.get(self._scope, chain_key(effect.run_id))
        ops.append(
            Check(chain_key(effect.run_id), Absent() if chain is None else VersionIs(chain.version))
        )
        for name in effect.requires_gates:
            latest = self._latest_gate(pk, name)
            if latest is None:
                return "gate_invalid"
            item, gate = latest
            # A round opened after this read commits nothing the item checks, so also require that
            # the next round is absent (rounds can skip numbers: the chain check covers those).
            ops.append(Check(item.key, VersionIs(item.version)))
            ops.append(Check(gate_key(effect.run_id, name, gate.round + 1), Absent()))
            if (
                gate.status is not GateStatus.APPROVED
                or gate.subject.head_sha != reference.head_sha
            ):
                return "gate_invalid"
            own = gate.subject.digest()
            approvals = [
                d.id
                for d in (
                    from_wire(Decision, i.data)
                    for i in self._pages(self._scope, pk, decision_prefix(name, gate.round))
                )
                if d.gate_id == gate.id and d.kind in _APPROVING and d.subject_digest == own
            ]
            if not approvals:
                return "gate_invalid"
            found.extend(approvals)
        return tuple(found)

    def _frozen_subject(self, run_id: RunId) -> Subject | None:
        merged = [
            r.effect
            for r in self._all(run_id)
            if r.effect.status is EffectStatus.CONFIRMED and r.effect.frozen_subject
        ]
        latest = max(merged, key=lambda e: e.id.value, default=None)  # ULIDs sort by planning time
        return latest.frozen_subject if latest else None

    def _latest_gate(self, pk: str, name: str) -> tuple[Item, Gate] | None:
        prefix = gate_prefix(name)
        rounds = [
            (int(i.key.sk[len(prefix) :]), i)
            for i in self._pages(self._scope, pk, prefix)
            if i.key.sk[len(prefix) :].isdigit()  # "GATE#a#" must not match gate "a#b"
        ]
        if not rounds:
            return None
        item = max(rounds, key=lambda r: r[0])[1]
        return item, from_wire(Gate, item.data)

    # --- write and settle -------------------------------------------------------------------

    def _write(
        self, run_id: RunId, idempotency_key: str, token: str, handler: EffectHandler
    ) -> ExecResult:
        rec = self._load(run_id, idempotency_key)
        if rec.effect.status is not EffectStatus.ATTEMPTING or rec.meta.get("lease_owner") != token:
            return self._replay(rec, "lease_lost")  # taken over before we wrote anything
        outcome: Outcome | _Retry
        try:
            outcome = handler.execute(rec.effect)
        except TransientError:
            outcome = _Retry("transient")
        except StaleHeadError as exc:
            on_edge = rec.effect.type in STALE_EDGE_TYPES
            outcome = Failed(
                "stale" if on_edge else None, "stale_head" if on_edge else type(exc).__name__
            )
        except PermanentError as exc:
            outcome = Failed(None, type(exc).__name__)
        return self._settle(run_id, idempotency_key, outcome, EffectStatus.ATTEMPTING, token)

    def _settle(
        self,
        run_id: RunId,
        idempotency_key: str,
        outcome: Outcome | _Retry,
        expect: EffectStatus,
        token: str | None = None,
        *,
        recovered: bool = False,
    ) -> ExecResult:
        """Apply ``outcome`` at the version it is decided on. If the record moved, re-read: a
        state that is no longer ``expect`` (or no longer ours) is reported, never overwritten.
        ``recovered`` settles the outcome of a lost attempt (RETRYING, or ATTEMPTING whose lease
        lapsed), which counts as the attempt it was."""
        for _ in range(_TRIES):
            rec = self._load(run_id, idempotency_key)
            effect = rec.effect
            if effect.status is not expect or (token and rec.meta.get("lease_owner") != token):
                return self._replay(rec, "lease_lost" if token else "superseded")
            if recovered:
                if effect.status is EffectStatus.ATTEMPTING and self._leased(rec):
                    return ExecResult(effect, reason="in_flight")
                if effect.status is EffectStatus.RETRYING and not isinstance(outcome, Voided):
                    rec = dataclasses.replace(rec, effect=effect.advance(EffectStatus.ATTEMPTING))
            try:
                return self._apply(rec, outcome)
            except (ConditionFailedError, TransactionConflictError):
                continue
        raise TransientError(f"effect {idempotency_key!r} kept changing while settling")

    def _leased(self, rec: _Rec) -> bool:
        return self._clock() < float(rec.meta.get("lease_until", 0.0))

    def _apply(self, rec: _Rec, outcome: Outcome | _Retry) -> ExecResult:
        effect = rec.effect
        attempting = effect.status is EffectStatus.ATTEMPTING

        def move(
            target: EffectStatus, edge: str | None, reason: str | None, **fields: Any
        ) -> ExecResult:
            base = (
                effect.advance(EffectStatus.RETRYING)
                if attempting and (target is EffectStatus.VOIDED)
                else effect
            )  # ATTEMPTING -> RETRYING -> VOIDED: a lost attempt that was dequeued
            done = base.advance(target, **fields)
            self._save(rec, done, {"edge": edge, "reason": reason})
            return ExecResult(done, edge, reason)

        match outcome:
            case Written(receipt, frozen) if receipt.read_back_verified:
                return move(
                    EffectStatus.CONFIRMED, "done", None, receipt=receipt, frozen_subject=frozen
                )
            case Written() | Pending() if effect.status is EffectStatus.ACCEPTED:
                return ExecResult(effect, reason="unconfirmed")  # still ACCEPTED
            case Written():  # accepted, but read-back did not show it applied
                return self._retry(rec, "read_back_failed")
            case _Retry(reason):
                return self._retry(rec, reason)
            case Pending(intent, receipt):
                return move(EffectStatus.ACCEPTED, None, None, receipt=receipt, intent=intent)
            case Failed(edge, reason):
                return move(EffectStatus.FAILED, edge, reason)
            case Voided(reason):
                return move(EffectStatus.VOIDED, None, reason)  # keeps the merge handle as intent
        raise ValueError(f"an {effect.status.value} effect cannot take {outcome!r}")

    def _retry(self, rec: _Rec, reason: str) -> ExecResult:
        """Another try with the same key; after ``max_attempts`` the outcome is unknown, which
        blocks the run rather than guessing (ADR-0011)."""
        effect = rec.effect.advance(EffectStatus.RETRYING)
        if effect.attempts - int(rec.meta.get("floor", 0)) >= self._max:
            meta = {"reason": "attempts_exhausted", "blocked": f"attempts_exhausted:{reason}"}
            self._save(rec, effect, meta)
            return ExecResult(effect, reason="attempts_exhausted", blocked=True)
        self._save(rec, effect, {"reason": reason})
        return ExecResult(effect, reason=reason)

    # --- ACCEPTED: poll and stop ------------------------------------------------------------

    def poll(self, run_id: RunId, idempotency_key: str, handler: EffectHandler) -> ExecResult:
        effect = self._accepted(run_id, idempotency_key)
        return self._settle(run_id, idempotency_key, handler.poll(effect), EffectStatus.ACCEPTED)

    def stop(self, run_id: RunId, idempotency_key: str, handler: EffectHandler) -> ExecResult:
        """Stop for an ACCEPTED effect: cancel it if possible, then reconcile with what the
        service says. It never blocks over a merge that is already dead or landed."""
        effect = self._accepted(run_id, idempotency_key)
        return self._settle(run_id, idempotency_key, handler.stop(effect), EffectStatus.ACCEPTED)

    def reconcile(self, run_id: RunId, idempotency_key: str, handler: EffectHandler) -> ExecResult:
        """Stop's route for an attempt whose answer was lost (RETRYING, or ATTEMPTING with a lapsed
        lease), and for an ACCEPTED one: ask the writer what became of it, dequeue it if it is
        still pending, and settle from what is read back (PLAN 14.3, D2-11). It never voids a
        write that may have landed, and never writes anew if the run is stopping. A merge that
        cannot be found (moved head, closed PR) stays blocked for a person."""
        rec = self._load(run_id, idempotency_key)
        status = rec.effect.status
        if status is EffectStatus.ACCEPTED:
            return self.stop(run_id, idempotency_key, handler)
        if status is EffectStatus.ATTEMPTING and self._leased(rec):
            return ExecResult(rec.effect, reason="in_flight")
        if status not in (EffectStatus.ATTEMPTING, EffectStatus.RETRYING):
            raise ValueError(f"nothing to reconcile in a {status.value} effect")
        try:
            outcome = handler.reconcile(rec.effect)
        except (StaleHeadError, RefusedError) as exc:
            return self._block(rec, f"unreconciled:{type(exc).__name__}")
        return self._settle(run_id, idempotency_key, outcome, status, recovered=True)

    def _accepted(self, run_id: RunId, idempotency_key: str) -> Effect:
        effect = self.get(run_id, idempotency_key)
        if effect.status is not EffectStatus.ACCEPTED:
            raise ValueError(
                f"only an ACCEPTED effect can be polled or stopped, not {effect.status.value}"
            )
        return effect

    # --- cancel -----------------------------------------------------------------------------

    def void_planned(self, run_id: RunId) -> StopReport:
        """PLAN 14.3 step 1: void every PLANNED effect of the run. Anything already tried
        (ATTEMPTING, RETRYING, ACCEPTED) may have landed, so it is reported instead, never voided.
        Each void is conditional on the effect's version, so against a concurrent claim exactly
        one wins."""
        voided: list[Effect] = []
        in_flight: list[Effect] = []
        for first in self._all(run_id):
            key = first.effect.idempotency_key
            for _ in range(_TRIES):
                rec = self._load(run_id, key)
                if rec.effect.status is EffectStatus.PLANNED:
                    done = rec.effect.advance(EffectStatus.VOIDED)
                    try:
                        self._save(rec, done, {"reason": "cancelled"})
                    except (ConditionFailedError, TransactionConflictError):
                        continue  # a claim won; re-read and report it as in flight
                    voided.append(done)
                elif rec.effect.status in (
                    EffectStatus.ATTEMPTING,
                    EffectStatus.RETRYING,
                    EffectStatus.ACCEPTED,
                ):
                    in_flight.append(rec.effect)
                break
        return StopReport(tuple(voided), tuple(in_flight))
