"""The audit port offers no way to update or delete, and refused attempts go aside."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from audit.helpers import RUN, TEAM, Recorder, audit_items, template_run
from sto.audit.errors import AuditVerificationError
from sto.audit.port import AuditLog, RefusedAttempts, StoreAuditLog
from sto.gates.hooks import ChainedAuditWriter, audit_pk
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
    template_run(GateService(rec, audit=ChainedAuditWriter()), RUN)
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
    rec_ops = ChainedAuditWriter()
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
    template_run(GateService(rec, audit=ChainedAuditWriter()), RUN)
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


def refused_items(store: MemoryStore, partition: str) -> list[Any]:
    return list(store.query(TEAM, f"REFUSED#{partition}", table=AUDIT).items)


GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def test_a_refused_attempt_is_stored_outside_the_chain_and_redacted() -> None:
    store, count = MemoryStore(), Counter()
    RefusedAttempts(store, count).record(
        TEAM,
        RUN,
        actor="mallory",
        action=f"gate.decide {GH}",
        reason=f"not eligible {GH}",
        data={"token": "abc", "comment": GH},
        at=5,
    )
    (item,) = refused_items(store, str(RUN))
    assert item.data["reason"] == "not eligible [REDACTED]"
    assert item.data["action"] == "gate.decide [REDACTED]"
    assert item.data["actor"] == "mallory"
    assert item.data["data"] == {"token": "[REDACTED]", "comment": "[REDACTED]"}
    assert audit_items(store, RUN) == []  # the run's chain is untouched
    assert store.get(TEAM, Key(f"RUN#{RUN}", "CHAIN")) is None
    assert count.names == []


def test_padding_an_attempt_cannot_erase_its_record() -> None:
    store, count = MemoryStore(), Counter()
    ra = RefusedAttempts(store, count)
    ra.record(
        TEAM, RUN, actor="m" * 10_000, action="a" * 50_000, reason="r" * 900_000,
        data={"x": "y" * 500_000, "nested": ["z" * 100_000] * 20}, at=1,
    )  # fmt: skip
    (item,) = refused_items(store, str(RUN))
    assert count.names == []
    assert item.data["data"]["truncated"] is True
    assert item.data["data"]["bytes"] > 400_000
    assert len(item.data["actor"]) < 2_000
    assert len(item.data["action"]) < 2_000
    assert len(item.data["reason"]) < 2_000
    assert item.data["at"] == 1
    assert item.data["run"] == str(RUN)


def test_a_small_attempt_keeps_its_data_untruncated() -> None:
    store = MemoryStore()
    RefusedAttempts(store, Counter()).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={"k": [1, 2]}, at=1
    )
    assert refused_items(store, str(RUN))[0].data["data"] == {"k": [1, 2]}


@pytest.mark.parametrize("bad", ["not-a-run", "x\n[OK] verified", "", "../" * 100])
def test_a_bad_run_id_is_recorded_as_unattributed_not_dropped(bad: str) -> None:
    store, count = MemoryStore(), Counter()
    RefusedAttempts(store, count).record(
        TEAM, bad, actor="a", action="x", reason="r", data={}, at=1
    )
    (item,) = refused_items(store, "unattributed")
    assert item.data["claimed_run"] == bad[:1024]
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


def test_unserialisable_data_is_counted_not_raised() -> None:
    count = Counter()
    RefusedAttempts(MemoryStore(), count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={"k": object()}, at=1
    )
    assert count.names == [] or count.names == ["audit.refused_write_failed"]


def test_a_failing_metric_does_not_break_the_best_effort_path() -> None:
    class Broken(MemoryStore):
        def transact(self, scope: Any, ops: Any) -> None:
            raise RuntimeError("down")

    def bad(_name: str) -> None:
        raise RuntimeError("metrics down")

    RefusedAttempts(Broken(), bad).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={}, at=1
    )


def test_the_log_holds_a_read_only_view_of_the_store() -> None:
    log = StoreAuditLog(MemoryStore())
    view = log._view
    assert not hasattr(view, "transact")
    assert not hasattr(view, "put")
    assert not hasattr(view, "delete")


def test_a_malformed_head_item_is_a_verification_error_not_a_keyerror() -> None:
    store = MemoryStore()
    store.transact(TEAM, [Put(Key(f"RUN#{RUN}", "CHAIN"), {"x": 1})])
    with pytest.raises(AuditVerificationError, match="malformed"):
        StoreAuditLog(store).head(TEAM, RUN)
