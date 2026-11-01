"""The audit port offers no way to update or delete, and refused attempts go aside."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from audit.helpers import RUN, TEAM, Recorder, audit_items, template_run
from sto.audit.chain import AuditChainWriter
from sto.audit.port import AuditLog, RefusedAttempts, StoreAuditLog
from sto.gates.hooks import audit_pk
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import AUDIT, Absent, Delete, Key, Put
from sto.store.sqlite import SqliteStore

MUTATORS = {"update", "delete", "put", "set", "remove", "replace", "transact", "write", "truncate"}


def public(obj: object) -> set[str]:
    return {n for n, _ in inspect.getmembers(obj) if not n.startswith("_")}


def test_the_port_has_no_mutating_method() -> None:
    assert not (public(AuditLog) & MUTATORS)
    assert not (public(StoreAuditLog) & MUTATORS)
    assert public(AuditLog) == {"entries", "head"}


def test_the_port_reads_what_the_writer_stored() -> None:
    rec = Recorder()
    template_run(GateService(rec, audit=AuditChainWriter()), RUN)
    log = StoreAuditLog(rec.inner, page_size=2)
    got = [dict(e) for e in log.entries(TEAM, RUN)]
    assert got == audit_items(rec.inner, RUN)
    head = log.head(TEAM, RUN)
    assert head is not None
    assert head.seq == len(got)
    assert head.hash == got[-1]["hash"]


@pytest.mark.parametrize("make", [lambda _p: MemoryStore(), lambda p: SqliteStore(str(p / "s.db"))])
def test_the_store_refuses_to_replace_or_delete_an_audit_entry(make: Any, tmp_path: Path) -> None:
    store = make(tmp_path)
    rec_ops = AuditChainWriter()
    from audit.helpers import subject
    from sto.domain import GateType
    from sto.engine.commands import OpenGate

    GateService(store, audit=rec_ops).open_gate(
        TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject())
    )
    key = Key(audit_pk(RUN), f"{1:012d}", AUDIT)
    with pytest.raises(ValueError, match="append-only"):
        store.transact(TEAM, [Delete(key)])
    with pytest.raises(ValueError, match="append-only"):
        store.transact(TEAM, [Put(key, {"x": 1})])
    with pytest.raises(ValueError, match="append-only"):
        store.transact(TEAM, [Put(key, {"x": 1}, None)])
    from sto.store.ports import ConditionFailedError

    with pytest.raises(ConditionFailedError):
        store.transact(
            TEAM, [Put(key, {"x": 1}, Absent())]
        )  # the one allowed write cannot overwrite


def test_the_writer_only_ever_emits_absent_puts_to_the_audit_table() -> None:
    rec = Recorder()
    template_run(GateService(rec, audit=AuditChainWriter()), RUN)
    for _, ops in rec.committed:
        for op in ops:
            if op.key.table == AUDIT:
                assert isinstance(op, Put)
                assert op.when == Absent()


# --- refused attempts ---------------------------------------------------------------------------


class Counter:
    def __init__(self) -> None:
        self.names: list[str] = []

    def __call__(self, name: str) -> None:
        self.names.append(name)


def test_a_refused_attempt_is_stored_outside_the_chain_and_redacted() -> None:
    store, count = MemoryStore(), Counter()
    refused = RefusedAttempts(store, count)
    refused.record(
        TEAM,
        RUN,
        actor="mallory",
        action="gate.decide",
        reason="not eligible",
        data={"token": "abc", "comment": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"},
        at=5,
    )
    items = store.query(TEAM, f"REFUSED#{RUN}", table=AUDIT).items
    assert len(items) == 1
    assert items[0].data["reason"] == "not eligible"
    assert "ghp_" not in str(items[0].data)
    assert "abc" not in str(items[0].data)
    assert audit_items(store, RUN) == []  # the run's chain is untouched
    assert store.get(TEAM, Key(f"RUN#{RUN}", "CHAIN")) is None
    assert count.names == []


def test_a_store_failure_never_reaches_the_caller_and_is_counted() -> None:
    class Broken(MemoryStore):
        def transact(self, scope: Any, ops: Any) -> None:
            raise RuntimeError("table unavailable")

    count = Counter()
    RefusedAttempts(Broken(), count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={}, at=1
    )
    assert count.names == ["audit.refused_write_failed"]


def test_a_failing_metric_does_not_break_the_best_effort_path() -> None:
    class Broken(MemoryStore):
        def transact(self, scope: Any, ops: Any) -> None:
            raise RuntimeError("down")

    def bad(_name: str) -> None:
        raise RuntimeError("metrics down")

    RefusedAttempts(Broken(), bad).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={}, at=1
    )
