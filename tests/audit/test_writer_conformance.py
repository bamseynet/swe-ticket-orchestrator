"""Every audit writer in the codebase passes the conformance suite, and none escapes it."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest

import sto
from audit.helpers import RUN, TEAM, Recorder, audit_items, template_run
from audit.writer_conformance import AuditWriterConformance
from sto.audit.chain import AuditChainWriter
from sto.audit.verify import verify_run
from sto.domain import DecisionKind, Surface
from sto.gates.hooks import AuditWriter, ChainedAuditWriter
from sto.gates.service import GateClosedError, GateService
from sto.store.ports import AUDIT, Check, Exists, Key, Put

REGISTERED = (ChainedAuditWriter, AuditChainWriter)


class TestChainedAuditWriter(AuditWriterConformance):
    def make_writer(self) -> AuditWriter:
        return ChainedAuditWriter()


class TestAuditChainWriter(AuditWriterConformance):
    def make_writer(self) -> AuditWriter:
        return AuditChainWriter()


class _NoHead:
    """Records an entry but leaves the chain head alone: what the conformance suite must catch."""

    def ops(self, reader, scope, entry):  # type: ignore[no-untyped-def]
        return [Put(Key(f"RUN#{entry.run_id}", f"{entry.action}-{entry.at}", AUDIT), {"a": 1})]


class _CheckOnlyHead(ChainedAuditWriter):
    """Reads the head into a Check instead of moving it."""

    def ops(self, reader, scope, entry):  # type: ignore[no-untyped-def]
        return [
            Check(Key(f"RUN#{entry.run_id}", "CHAIN"), Exists()) if o.key.sk == "CHAIN" else o
            for o in super().ops(reader, scope, entry)
        ]


class TestTheSuiteCatchesBadWriters:
    def _fails(self, writer: AuditWriter) -> bool:
        class Probe(AuditWriterConformance):
            def make_writer(self) -> AuditWriter:
                return writer

        probe = Probe()
        for name in (n for n in dir(Probe) if n.startswith("test_")):
            try:
                getattr(probe, name)()
            except Exception:
                return True
        return False

    def test_a_writer_that_skips_the_head_fails(self) -> None:
        assert self._fails(_NoHead())

    def test_a_writer_that_only_checks_the_head_fails(self) -> None:
        assert self._fails(_CheckOnlyHead())


def _audit_writer_classes() -> set[type]:
    """Every class under ``src/sto`` shaped like an ``AuditWriter`` (found on disk, because
    ``sto.gates`` and others are namespace packages that ``pkgutil.walk_packages`` skips)."""
    found: set[type] = set()
    root = Path(sto.__path__[0])
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root.parent).with_suffix("").parts
        module = importlib.import_module(".".join(p for p in parts if p != "__init__"))
        for _, cls in inspect.getmembers(module, inspect.isclass):
            fn = getattr(cls, "ops", None)
            if (
                cls.__module__ == module.__name__
                and callable(fn)
                and not getattr(cls, "_is_protocol", False)
            ) and list(inspect.signature(fn).parameters) == ["self", "reader", "scope", "entry"]:
                found.add(cls)
    return found


def test_every_audit_writer_in_the_codebase_is_registered_for_conformance() -> None:
    assert _audit_writer_classes() == set(REGISTERED), (
        "a new AuditWriter must be added to REGISTERED and get a conformance subclass"
    )
    tested = {
        c.make_writer(c()).__class__
        for c in AuditWriterConformance.__subclasses__()
        if c.__name__.startswith("Test")
    }
    assert tested >= set(REGISTERED)


# --- every state change is audited ---------------------------------------------------------------


def test_every_state_change_of_a_template_run_has_one_audit_event() -> None:
    rec = Recorder()
    service = GateService(rec, audit=AuditChainWriter())
    changes = template_run(service, RUN)

    state_txs = [ops for _, ops in rec.committed if any(o.key.table != AUDIT for o in ops)]
    assert len(state_txs) == changes
    for ops in state_txs:
        assert sum(1 for o in ops if o.key.table == AUDIT) == 1, "one audit entry per change"
    entries = audit_items(rec.inner, RUN)
    assert len(entries) == changes
    assert [e["action"] for e in entries] == [
        "gate.opened", "gate.decided", "gate.opened", "gate.decided",
        "gate.opened", "gate.decided", "gate.opened", "gate.decided",
    ]  # fmt: skip
    assert verify_run(rec.inner, TEAM, RUN) == changes


def test_a_refused_decision_leaves_no_audit_entry() -> None:
    rec = Recorder()
    service = GateService(rec, audit=AuditChainWriter())
    template_run(service, RUN)
    n = len(audit_items(rec.inner, RUN))
    with pytest.raises(GateClosedError):
        service.decide(
            TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.APPROVE,
            actor="x", surface=Surface.UI, subject_digest="nope",
        )  # fmt: skip
    assert len(audit_items(rec.inner, RUN)) == n
