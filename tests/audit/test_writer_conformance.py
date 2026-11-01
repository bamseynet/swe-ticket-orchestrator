"""Every audit writer passes the conformance suite, and none can hide from it."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

import sto
from audit import writer_scan
from audit.helpers import RUN, TEAM, Recorder, audit_items, template_run
from audit.writer_conformance import AuditWriterConformance
from sto.audit.errors import AuditVerificationError
from sto.audit.verify import verify_run
from sto.domain import DecisionKind, Surface
from sto.gates.hooks import (
    GENESIS_HASH,
    AuditEntry,
    AuditWriter,
    ChainedAuditWriter,
    Reader,
    entry_hash,
)
from sto.gates.service import GateClosedError, GateService
from sto.store.ports import AUDIT, Absent, Check, Key, Op, Put, Scope, VersionIs

SRC = Path(sto.__path__[0])
REGISTERED = {"ChainedAuditWriter"}
ALLOWED = {
    "sto/audit/port.py",  # RefusedAttempts writes its own partition, never a run's chain
    "sto/effects/ports.py",  # names the CHAIN key to check it
    "sto/gates/hooks.py",
    "sto/gates/service.py",
    "sto/store/ports.py",
}


class TestChainedAuditWriter(AuditWriterConformance):
    def make_writer(self) -> AuditWriter:
        return ChainedAuditWriter()


# --- the scan: real code, then planted writers it must catch ------------------------------------


def test_the_scan_reads_the_codebase_and_finds_exactly_the_registered_writers() -> None:
    sources = writer_scan.read_sources(SRC)
    assert len(sources) > 20, "the scan must see the whole of src/sto"
    found = {
        c for _, text in sources for c in writer_scan.writer_classes(__import__("ast").parse(text))
    }
    assert found == REGISTERED
    assert writer_scan.violations(sources, ALLOWED, REGISTERED) == []
    assert {Path(p).name for p, _ in sources} >= {"hooks.py", "service.py", "core.py"}


def test_every_registered_writer_has_a_conformance_subclass() -> None:
    covered = {type(c().make_writer()).__name__ for c in AuditWriterConformance.__subclasses__()}
    assert covered == REGISTERED


PLANTED = {
    "renamed parameters": "class W:\n    def ops(self, r, s, e): return []\n",
    "star args": "class W:\n    def ops(self, *a, **k): return []\n",
    "extra keyword": "class W:\n    def ops(self, reader, scope, entry, *, x=None): return []\n",
    "callable": "class W:\n    def __call__(self, reader, scope, entry): return []\n",
    "annotated, other name": (
        "from sto.gates.hooks import AuditEntry\n"
        "class W:\n    def build(self, x: AuditEntry): return []\n"
    ),
    "nested class": "class Holder:\n    class W:\n        def ops(self, a, b, c): return []\n",
    "factory": (
        "def make():\n    class W:\n        def ops(self, a, b, c): return []\n    return W\n"
    ),
    "direct transact": (
        "from sto.store.ports import AUDIT, Absent, Key, Put\n"
        "def write(store, scope, entry):\n"
        "    store.transact(scope, [Put(Key('RUN#x', '1', AUDIT), {'a': 1}, Absent())])\n"
    ),
    "string literal table": "def w(store, s):\n    store.put(s, Key('p', 'k', 'audit'), {})\n",
    "string literal head": "def w(store, s):\n    store.put(s, Key('RUN#x', 'CHAIN'), {})\n",
    "wraps the writer": (
        "from sto.gates.hooks import ChainedAuditWriter\n"
        "class Mine(ChainedAuditWriter):\n    pass\n"
    ),
}


@pytest.mark.parametrize("name", PLANTED)
def test_the_scan_catches_a_planted_writer_outside_the_allow_list(name: str) -> None:
    found = writer_scan.violations([("sto/rogue.py", PLANTED[name])], ALLOWED, REGISTERED)
    assert found, f"a {name} writer got past the scan"
    assert all(line.startswith("sto/rogue.py") for line in found)


def test_the_scan_catches_an_unregistered_class_inside_an_allowed_module() -> None:
    src = "class Sneaky:\n    def ops(self, a, b, c): return []\n"
    found = writer_scan.violations([("sto/gates/hooks.py", src)], ALLOWED, REGISTERED)
    assert found
    assert "unregistered" in found[0]


def test_the_scan_leaves_protocols_and_registered_writers_alone() -> None:
    src = (
        "from typing import Protocol\n"
        "class P(Protocol):\n    def ops(self, r, s, e): ...\n"
        "class ChainedAuditWriter:\n    def ops(self, r, s, e): return []\n"
    )
    assert writer_scan.violations([("sto/gates/hooks.py", src)], ALLOWED, REGISTERED) == []


# --- the suite itself: each bad writer must fail for the reason it is named for ----------------


def entry_op(reader: Reader, scope: Scope, entry: AuditEntry) -> Put:
    """A correct chained entry, positioned from the audit table itself, so that a writer built
    on it differs from the real one only in how it treats the chain head."""
    items = reader.query(scope, f"RUN#{entry.run_id}", table=AUDIT).items
    prev = items[-1].data["hash"] if items else GENESIS_HASH
    body = {
        "run": str(entry.run_id), "team": "t1", "seq": len(items) + 1, "at": entry.at,
        "action": entry.action, "actor": entry.actor, "data": entry.data, "prev": prev,
    }  # fmt: skip
    return Put(
        Key(f"RUN#{entry.run_id}", f"{len(items) + 1:012d}", AUDIT),
        {**body, "hash": entry_hash(body)},
        Absent(),
    )


class NoHead:
    """A valid chained entry, but the chain head is left alone."""

    def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> Sequence[Op]:
        return [entry_op(reader, scope, entry)]


class CheckOnlyHead:
    """Checks the head at the right version instead of moving it."""

    def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> Sequence[Op]:
        key = Key(f"RUN#{entry.run_id}", "CHAIN")
        head = reader.get(scope, key)
        return [
            entry_op(reader, scope, entry),
            Check(key, Absent() if head is None else VersionIs(head.version)),
        ]


class Garbage:
    """A correct head move around an entry that is not a chain link."""

    def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> Sequence[Op]:
        head_key = Key(f"RUN#{entry.run_id}", "CHAIN")
        head = reader.get(scope, head_key)
        seq = 1 if head is None else int(head.data["seq"]) + 1
        return [
            Put(Key(f"RUN#{entry.run_id}", f"{seq:012d}", AUDIT), {"junk": 1}, Absent()),
            Put(
                head_key,
                {"seq": seq, "hash": "h"},
                Absent() if head is None else VersionIs(head.version),
            ),
        ]


class Unconditional:
    """Moves the head without the version condition: two writers could take one seq."""

    def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> Sequence[Op]:
        return [
            Put(op.key, op.data, None) if op.key.sk == "CHAIN" and isinstance(op, Put) else op
            for op in ChainedAuditWriter().ops(reader, scope, entry)
        ]


OPEN = "test_open_moves_the_chain_head_in_the_same_transaction"
DECIDE = "test_decide_moves_the_chain_head_in_the_same_transaction"
CHAINS = "test_what_it_stores_verifies_as_a_chain"
MISSING = "the chain head must exist"
# writer, exception type, reason that must appear on at least one test, and the exact tests that
# must fail (and with which reason: a substring of the message)
BAD: list[tuple[type, type[BaseException], dict[str, str]]] = [
    (NoHead, AssertionError, {OPEN: "chain head exactly once", DECIDE: MISSING}),
    (CheckOnlyHead, AssertionError, {OPEN: "written, not just checked", DECIDE: MISSING}),
    (Garbage, AuditVerificationError, {CHAINS: "wrong run or team"}),
    (Unconditional, AssertionError, {OPEN: "", DECIDE: ""}),  # each test sees the missing condition
]


def failures_of(writer: AuditWriter) -> dict[str, BaseException]:
    class Probe(AuditWriterConformance):
        def make_writer(self) -> AuditWriter:
            return writer

    probe, out = Probe(), {}
    for name in sorted(n for n in dir(Probe) if n.startswith("test_")):
        try:
            getattr(probe, name)()
        except BaseException as exc:  # the type is what is being asserted on
            out[name] = exc
    return out


@pytest.mark.parametrize(("cls", "exc_type", "tests"), BAD, ids=[b[0].__name__ for b in BAD])
def test_a_bad_writer_fails_the_suite_for_its_reason(
    cls: Any, exc_type: type[BaseException], tests: dict[str, str]
) -> None:
    failed = failures_of(cls())
    assert failed, f"{cls.__name__} passed the whole suite"
    for name, reason in tests.items():
        got = failed.get(name)
        assert got is not None, f"{name} did not fail for {cls.__name__}"
        assert type(got) is exc_type
        assert reason in str(got)
    unexpected = {
        n: e
        for n, e in failed.items()
        if not isinstance(e, AssertionError | AuditVerificationError)
    }
    assert not unexpected, f"failed for an incidental reason: {unexpected}"


def test_the_real_writer_fails_nothing() -> None:
    assert failures_of(ChainedAuditWriter()) == {}


# --- gate sequence: every gate open and decision is audited -------------------------------------


def test_every_gate_open_and_decision_of_a_template_shaped_sequence_has_one_audit_event() -> None:
    rec = Recorder()
    service = GateService(rec)
    changes = template_run(service, RUN)

    state_txs = [ops for _, ops in rec.committed if any(o.key.table != AUDIT for o in ops)]
    assert len(state_txs) == changes
    for ops in state_txs:
        assert sum(1 for o in ops if o.key.table == AUDIT) == 1, "one audit entry per change"
    entries = audit_items(rec.inner, RUN)
    assert len(entries) == changes
    assert [e["action"] for e in entries] == ["gate.opened", "gate.decided"] * 4
    assert verify_run(rec.inner, TEAM, RUN) == changes


def test_a_refused_decision_leaves_no_audit_entry() -> None:
    rec = Recorder()
    service = GateService(rec)
    template_run(service, RUN)
    n = len(audit_items(rec.inner, RUN))
    with pytest.raises(GateClosedError):
        service.decide(
            TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.APPROVE,
            actor="x", surface=Surface.UI, subject_digest="nope",
        )  # fmt: skip
    assert len(audit_items(rec.inner, RUN)) == n
