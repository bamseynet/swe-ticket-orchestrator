"""Conformance for every ``AuditWriter`` (D1-07 review ruling, D3-08).

A writer must move ``RUN#r/CHAIN`` in the same transaction as the gate open or decision it
records. The effect claim (``effects/core.py``) holds a ``Check`` on that item, which is how it
notices a gate round that skips numbers. Subclass ``AuditWriterConformance`` for a new writer."""

from __future__ import annotations

from typing import Any

from audit.helpers import RUN, TEAM, Recorder, audit_items, subject, template_run
from sto.audit.verify import verify_run
from sto.domain import DecisionKind, GateType, Surface
from sto.engine.commands import OpenGate
from sto.gates.hooks import AuditWriter, run_pk
from sto.gates.service import GateService
from sto.store.ports import AUDIT, Absent, Key, Put, VersionIs

CHAIN = Key(run_pk(RUN), "CHAIN")


class AuditWriterConformance:
    def make_writer(self) -> AuditWriter:
        raise NotImplementedError

    def _service(self) -> tuple[GateService, Recorder]:
        rec = Recorder()
        return GateService(rec, audit=self.make_writer()), rec

    def _head(self, rec: Recorder) -> Any:
        head = rec.get(TEAM, CHAIN)
        assert head is not None, "the chain head must exist after a gate change"
        return head

    def _chain_put(self, ops: Any) -> Put:
        puts = [o for o in ops if o.key == CHAIN]
        assert len(puts) == 1, "the transaction must write the chain head exactly once"
        assert isinstance(puts[0], Put), "the chain head must be written, not just checked"
        return puts[0]

    def test_what_it_stores_verifies_as_a_chain(self) -> None:
        """Moving the head is not enough: the entries must chain, hash and match the head."""
        service, rec = self._service()
        template_run(service, RUN)
        n = len(audit_items(rec.inner, RUN))
        assert n == 8
        assert verify_run(rec.inner, TEAM, RUN) == n

    def test_open_moves_the_chain_head_in_the_same_transaction(self) -> None:
        service, rec = self._service()
        service.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject()))
        ((_, ops),) = rec.committed
        assert self._chain_put(ops).when == Absent()
        assert any(o.key.table == AUDIT for o in ops)

    def test_decide_moves_the_chain_head_in_the_same_transaction(self) -> None:
        service, rec = self._service()
        service.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject()))
        before = self._head(rec)
        service.decide(
            TEAM,
            run_id=RUN,
            gate="review",
            round=1,
            kind=DecisionKind.APPROVE,
            actor="bob",
            surface=Surface.UI,
            subject_digest=subject().digest(),
        )
        _, ops = rec.committed[-1]
        put = self._chain_put(ops)
        assert put.when == VersionIs(before.version)
        assert any(o.key.table != AUDIT and o.key.sk.startswith("DEC#") for o in ops)

    def test_the_head_version_changes_on_every_gate_change(self) -> None:
        """What the effect claim's ``Check`` relies on: a gate round that skips numbers still
        changes the head, so a claim read before it can no longer commit."""
        service, rec = self._service()
        seen: list[int] = []
        for rnd in (1, 3):  # round 3 skips 2
            service.open_gate(
                TEAM, OpenGate(RUN, "review", GateType.REVIEW, rnd, subject(str(rnd)))
            )
            head = self._head(rec)
            seen.append(head.version)
            service.decide(
                TEAM, run_id=RUN, gate="review", round=rnd, kind=DecisionKind.REJECT,
                actor="x", surface=Surface.UI, subject_digest=subject(str(rnd)).digest(),
                comment="no",
            )  # fmt: skip
            seen.append(self._head(rec).version)
        assert seen == sorted(set(seen))
        assert len(seen) == 4

    def test_a_stale_claim_check_on_the_head_cannot_commit_after_a_round_that_skips(self) -> None:
        from sto.store.ports import Check, ConditionFailedError

        service, rec = self._service()
        service.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject("a")))
        service.decide(
            TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.REJECT, actor="x",
            surface=Surface.UI, subject_digest=subject("a").digest(), comment="no",
        )  # fmt: skip
        stale = self._head(rec)
        service.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 5, subject("b")))
        try:
            rec.transact(TEAM, [Check(CHAIN, VersionIs(stale.version))])
        except ConditionFailedError:
            return
        raise AssertionError("a Check on the stale head version still passed")
