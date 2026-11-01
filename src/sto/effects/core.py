"""Effects v0 (D1-07): plan, claim, write, settle (PLAN 6.3, 4.3 rules 1 and 5, ADR-0011).

The claim is one transaction. It writes the effect as ``ATTEMPTING`` and holds ``Check``s on the
run, on every required gate, and on the team and fleet switches, each at the version the guard
read. Stop, a gate decision or a switch flip commits a new version, so the claim and any of them
cannot both win; whichever loses re-reads. Only ``scoped`` and ``gated`` effects exist in v0.

Status comes only from a receipt: ``CONFIRMED`` needs one with read-back. A write the service
accepted but did not apply goes to ``RETRYING`` and is repeated with the same key.
"""

from __future__ import annotations

from dataclasses import dataclass

from sto.adapters.ports import StaleHeadError
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
    effect_key,
    from_wire,
    to_wire,
)
from sto.domain.errors import PermanentError, TransientError
from sto.store.ports import (
    PLATFORM,
    Absent,
    Check,
    ConditionFailedError,
    Item,
    Op,
    Put,
    Store,
    TeamScope,
    VersionIs,
)

from .ports import (
    FLEET_SWITCHES,
    STALE_EDGE_TYPES,
    TEAM_SWITCHES,
    EffectHandler,
    Failed,
    Outcome,
    Pending,
    Voided,
    Written,
    decision_prefix,
    effect_item_key,
    gate_prefix,
    run_key,
    run_pk,
    switch_field,
    switches_for,
)

_ACTIVE = frozenset({RunStatus.RUNNING, RunStatus.WAITING_EXTERNAL})
# A run in one of these will never act again, so its unwritten effects are voided. Any other
# inactive run (waiting, blocked, queued) only holds them: it may come back.
_DEAD = frozenset(
    {RunStatus.CANCELLING, RunStatus.CANCELLED, RunStatus.DONE, RunStatus.REJECTED}
    | {RunStatus.CLOSED, RunStatus.EXPIRED}
)
_APPROVING = frozenset({DecisionKind.APPROVE, DecisionKind.WAIVE})
_CLAIM_TRIES = 8


@dataclass(frozen=True)
class ExecResult:
    """``effect`` is the stored record after the call. ``edge`` is the workflow edge it took
    (``done``, ``stale``, ``conflict``), if any. ``reason`` says why nothing was written:
    ``gate_invalid``, ``run_not_active``, ``held``, ``unconfirmed``, or a failure name."""

    effect: Effect
    edge: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class StopReport:
    """What Stop found: effects it voided, and effects it could not (ATTEMPTING or ACCEPTED), which
    may have landed and need reconciling (PLAN 14.3)."""

    voided: tuple[Effect, ...] = ()
    in_flight: tuple[Effect, ...] = ()


def enable_switches(store: Store, scope: TeamScope, *names: str) -> None:
    """Turn team switches on (provisioning). A team's switch that was never written holds."""
    item = store.get(scope, TEAM_SWITCHES)
    data = dict(item.data) if item else {}
    data.update({switch_field(n): True for n in names})
    store.put(scope, TEAM_SWITCHES, data)


class _Claim:
    """The result of reading everything a claim depends on."""

    def __init__(self, ops: list[Op] | None = None, decisions: tuple[DecisionId, ...] = ()) -> None:
        self.ops = ops or []
        self.decisions = decisions


class EffectExecutor:
    def __init__(self, store: Store, scope: TeamScope, *, max_attempts: int = 3) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._store, self._scope, self._max = store, scope, max_attempts

    # --- plan and read ----------------------------------------------------------------------

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
    ) -> Effect:
        """Record a PLANNED effect, or return the one already planned under the same key.
        ``key`` overrides the default 5-tuple key for effects with a narrower scope (PLAN 6.3)."""
        if klass not in (EffectClass.SCOPED, EffectClass.GATED):
            raise ValueError("v0 plans scoped or gated effects only")
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
        item_key = effect_item_key(run_id, effect.idempotency_key)
        try:
            self._store.put(self._scope, item_key, to_wire(effect), when=Absent())
        except ConditionFailedError:
            existing = self.get(run_id, effect.idempotency_key)
            if (existing.type, existing.klass, existing.subject_digest) != (
                type,
                klass,
                subject_digest,
            ):
                raise ValueError(
                    f"idempotency key {effect.idempotency_key!r} is already used by another effect"
                ) from None
            return existing
        return effect

    def get(self, run_id: RunId, idempotency_key: str) -> Effect:
        return self._load(run_id, idempotency_key)[0]

    def _load(self, run_id: RunId, idempotency_key: str) -> tuple[Effect, int]:
        item = self._store.get(self._scope, effect_item_key(run_id, idempotency_key))
        if item is None:
            raise KeyError(f"no effect {idempotency_key!r} in run {run_id}")
        return from_wire(Effect, item.data), item.version

    def _save(self, effect: Effect, version: int, *extra: Op) -> None:
        key = effect_item_key(effect.run_id, effect.idempotency_key)
        self._store.transact(
            self._scope, [Put(key, to_wire(effect), when=VersionIs(version)), *extra]
        )

    # --- execute ----------------------------------------------------------------------------

    def execute(self, run_id: RunId, idempotency_key: str, handler: EffectHandler) -> ExecResult:
        """Claim and write one effect, then settle it from the outcome. Safe to call again after
        ``RETRYING`` (or after a crash left it ``ATTEMPTING``): the same key goes to the writer."""
        for _ in range(_CLAIM_TRIES):
            effect, version = self._load(run_id, idempotency_key)
            if effect.status not in (EffectStatus.PLANNED, EffectStatus.RETRYING):
                if effect.status is EffectStatus.ATTEMPTING:  # a crashed worker's attempt
                    self._save(effect.advance(EffectStatus.RETRYING), version)
                    continue
                return ExecResult(effect)  # finished, or ACCEPTED and waiting for a poll
            verdict = self._guard(effect)
            if isinstance(verdict, str):
                return self._refuse(effect, version, verdict)
            claimed = effect.advance(
                EffectStatus.ATTEMPTING,
                decision_ids=verdict.decisions if effect.klass is EffectClass.GATED else None,
                subject_digest=effect.subject_digest,
            )
            try:
                self._save(claimed, version, *verdict.ops)
            except ConditionFailedError:
                continue  # Stop, a decision or a switch won the race: re-read and decide again
            return self._write(claimed, handler)
        raise TransientError(f"effect {idempotency_key!r} kept changing under the claim")

    def _refuse(self, effect: Effect, version: int, reason: str) -> ExecResult:
        if reason == "held":
            return ExecResult(effect, reason="held")
        try:
            voided = effect.advance(EffectStatus.VOIDED, intent=f"voided:{reason}")
            self._save(voided, version)
        except ConditionFailedError:  # lost to a cancel or another executor: report what is there
            return ExecResult(self.get(effect.run_id, effect.idempotency_key), reason=reason)
        return ExecResult(voided, reason=reason)

    def _guard(self, effect: Effect) -> _Claim | str:
        """Read what the claim depends on. Returns the claim's ``Check``s, or a refusal reason:
        ``run_not_active`` and ``gate_invalid`` void the effect, ``held`` leaves it as it is."""
        ops: list[Op] = []
        run_item = self._store.get(self._scope, run_key(effect.run_id))
        if run_item is None:
            return "run_not_active"
        run = from_wire(Run, run_item.data)
        if run.status in _DEAD:
            return "run_not_active"
        if run.status not in _ACTIVE:
            return "held"
        ops.append(Check(run_key(effect.run_id), VersionIs(run_item.version)))
        switches = self._switches(effect.type, ops)
        if switches is not None:
            return switches
        if effect.klass is not EffectClass.GATED:
            return _Claim(ops)
        decisions = self._approval(effect, ops)
        return decisions if isinstance(decisions, str) else _Claim(ops, decisions)

    def _switches(self, effect_type: str, ops: list[Op]) -> str | None:
        team = self._store.get(self._scope, TEAM_SWITCHES)
        if team is None or any(
            team.data.get(switch_field(n)) is not True for n in switches_for(effect_type)
        ):
            return "held"  # fail closed: a team switch must be written, and on
        ops.append(Check(TEAM_SWITCHES, VersionIs(team.version)))
        fleet = self._store.get(PLATFORM, FLEET_SWITCHES)
        if fleet is None:
            ops.append(Check(FLEET_SWITCHES, Absent(), PLATFORM))
        else:
            if any(fleet.data.get(switch_field(n)) is False for n in switches_for(effect_type)):
                return "held"
            ops.append(Check(FLEET_SWITCHES, VersionIs(fleet.version), PLATFORM))
        return None

    def _approval(self, effect: Effect, ops: list[Op]) -> tuple[DecisionId, ...] | str:
        """PLAN 6.4 guard 2: the latest instance of every required gate is approved at exactly the
        subject this effect carries, by at least one approving decision."""
        pk = run_pk(effect.run_id)
        found: list[DecisionId] = []
        for name in effect.requires_gates:
            latest = self._latest_gate(pk, name)
            if latest is None:
                return "gate_invalid"
            item, gate = latest
            if (
                gate.status is not GateStatus.APPROVED
                or gate.subject.digest() != effect.subject_digest
            ):
                return "gate_invalid"
            ops.append(Check(item.key, VersionIs(item.version)))
            page = self._store.query(self._scope, pk, sk_prefix=decision_prefix(name, gate.round))
            approvals = [
                d
                for d in (from_wire(Decision, i.data) for i in page.items)
                if d.gate_id == gate.id
                and d.kind in _APPROVING
                and d.subject_digest == effect.subject_digest
            ]
            if not approvals:
                return "gate_invalid"
            found.extend(d.id for d in approvals)
        return tuple(found)

    def _latest_gate(self, pk: str, name: str) -> tuple[Item, Gate] | None:
        prefix = gate_prefix(name)
        rounds = [
            (int(i.key.sk[len(prefix) :]), i)
            for i in self._store.query(self._scope, pk, sk_prefix=prefix).items
            if i.key.sk[len(prefix) :].isdigit()  # "GATE#a#" must not match gate "a#b"
        ]
        if not rounds:
            return None
        item = max(rounds, key=lambda r: r[0])[1]
        return item, from_wire(Gate, item.data)

    def _write(self, claimed: Effect, handler: EffectHandler) -> ExecResult:
        try:
            outcome: Outcome = handler.execute(claimed)
        except TransientError:
            return self._retry_or_fail(claimed, "transient")
        except StaleHeadError as exc:
            on_edge = claimed.type in STALE_EDGE_TYPES
            outcome = Failed(
                "stale" if on_edge else None, "stale_head" if on_edge else type(exc).__name__
            )
        except PermanentError as exc:
            outcome = Failed(None, type(exc).__name__)
        return self._settle(claimed, outcome)

    def _retry_or_fail(self, effect: Effect, reason: str) -> ExecResult:
        if effect.attempts >= self._max:
            return self._finish(effect, EffectStatus.FAILED, None, "attempts_exhausted")
        return self._finish(effect, EffectStatus.RETRYING, None, reason)

    def _finish(
        self,
        effect: Effect,
        target: EffectStatus,
        edge: str | None,
        reason: str | None,
        **fields: object,
    ) -> ExecResult:
        _, version = self._load(effect.run_id, effect.idempotency_key)
        done = effect.advance(target, **fields)  # type: ignore[arg-type]
        self._save(done, version)
        return ExecResult(done, edge, reason)

    def _settle(self, effect: Effect, outcome: Outcome) -> ExecResult:
        """Move ``effect`` (ATTEMPTING or ACCEPTED) according to what the writer reported."""
        attempting = effect.status is EffectStatus.ATTEMPTING
        match outcome:
            case Written(receipt, frozen) if receipt.read_back_verified:
                return self._finish(
                    effect,
                    EffectStatus.CONFIRMED,
                    "done",
                    None,
                    receipt=receipt,
                    frozen_subject=frozen,
                )
            case Written() | Pending() if not attempting:
                return ExecResult(effect, reason="unconfirmed")  # still ACCEPTED
            case Written():  # accepted, but read-back did not show it applied
                return self._retry_or_fail(effect, "read_back_failed")
            case Pending(intent, receipt):
                return self._finish(
                    effect, EffectStatus.ACCEPTED, None, None, receipt=receipt, intent=intent
                )
            case Failed(edge, reason):
                return self._finish(effect, EffectStatus.FAILED, edge, reason)
            case Voided(reason) if not attempting:
                return self._finish(
                    effect, EffectStatus.VOIDED, None, reason, intent=f"voided:{reason}"
                )
        raise ValueError(f"an {effect.status.value} effect cannot take {outcome!r}")

    # --- ACCEPTED: poll and stop ------------------------------------------------------------

    def poll(self, run_id: RunId, idempotency_key: str, handler: EffectHandler) -> ExecResult:
        effect = self._accepted(run_id, idempotency_key)
        return self._settle(effect, handler.poll(effect))

    def stop(self, run_id: RunId, idempotency_key: str, handler: EffectHandler) -> ExecResult:
        """Stop for an ACCEPTED effect: cancel it if possible, then reconcile with what the
        service says. It never blocks over a merge that is already dead or landed."""
        effect = self._accepted(run_id, idempotency_key)
        return self._settle(effect, handler.stop(effect))

    def _accepted(self, run_id: RunId, idempotency_key: str) -> Effect:
        effect = self.get(run_id, idempotency_key)
        if effect.status is not EffectStatus.ACCEPTED:
            raise ValueError(
                f"only an ACCEPTED effect can be polled or stopped, not {effect.status.value}"
            )
        return effect

    # --- cancel -----------------------------------------------------------------------------

    def void_planned(self, run_id: RunId) -> StopReport:
        """PLAN 14.3 step 1: void every PLANNED or RETRYING effect of the run. An effect that is
        ATTEMPTING or ACCEPTED is reported instead: it may have landed. Each void is conditional
        on the effect's version, so against a concurrent claim exactly one wins."""
        voided: list[Effect] = []
        in_flight: list[Effect] = []
        for item in self._store.query(self._scope, run_pk(run_id), sk_prefix="FX#").items:
            key = from_wire(Effect, item.data).idempotency_key
            for _ in range(_CLAIM_TRIES):
                effect, version = self._load(run_id, key)
                if effect.status in (EffectStatus.PLANNED, EffectStatus.RETRYING):
                    try:
                        done = effect.advance(EffectStatus.VOIDED, intent="voided:cancelled")
                        self._save(done, version)
                    except ConditionFailedError:
                        continue  # a claim won; re-read and report it as in flight
                    voided.append(done)
                elif effect.status in (EffectStatus.ATTEMPTING, EffectStatus.ACCEPTED):
                    in_flight.append(effect)
                break
        return StopReport(tuple(voided), tuple(in_flight))
