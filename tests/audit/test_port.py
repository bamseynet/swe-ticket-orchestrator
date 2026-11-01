"""The audit port offers no way to update or delete, and refused attempts go aside."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any, cast

import pytest

from audit.helpers import RUN, TEAM, Recorder, audit_items, template_run
from sto.audit.errors import AuditVerificationError
from sto.audit.port import MAX_TEXT_SLICE, AuditLog, ChainHead, RefusedAttempts, StoreAuditLog
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
        TEAM, RUN, actor="m" * 10_000, action="a " * 50_000, reason="r " * 900_000,
        data={"x": "y" * 500_000, "nested": ["z" * 100_000] * 20}, at=1,
    )  # fmt: skip
    (item,) = refused_items(store, str(RUN))
    assert count.names == []
    data = item.data["data"]
    assert set(data) == {"truncated", "bytes"}  # the size only: no preview of what was cut
    assert data["truncated"] is True
    assert data["bytes"] > 400_000
    for field in ("actor", "action", "reason"):
        assert len(item.data[field]) < 1_100
        assert item.data[field].endswith("...[truncated]")
    assert item.data["at"] == 1
    assert item.data["run"] == str(RUN)


SECRETS = {
    "password": ('password="{}"', "hunter2hunter2hunter2"),
    "password-bare": ("password={}", "hunter2hunter2hunter2"),
    "url": ("https://bob:{}@github.com/x", "hunter2hunter2hunter2"),
    "ghp": ("{}", GH),
    "akia": ("{}", "AKIA" + "ABCDEFGHIJKLMNOP"),
    "jwt": ("{}", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx.c2lnbmF0dXJlc2lnbmF0dXJl"),
    "bearer": ("Authorization: Bearer {}", "abcdef0123456789abcdefg"),
    "pem": ("-----BEGIN PRIVATE KEY-----\n{}", "MIIEvQIBADANBgkqhkiG9w0BAQ"),
    "spaced": ('password="{}"', "correct horse battery staple"),
}


def longest_piece(secret: str, out: str, floor: int = 6) -> str:
    """The longest slice of ``secret`` of at least ``floor`` characters found in ``out``."""
    for n in range(len(secret), floor - 1, -1):
        for i in range(len(secret) - n + 1):
            if secret[i : i + n] in out:
                return secret[i : i + n]
    return ""


@pytest.mark.parametrize("field", ["action", "reason"])
@pytest.mark.parametrize("name", SECRETS)
def test_no_part_of_a_secret_survives_the_bound_at_any_cut(name: str, field: str) -> None:
    template, secret = SECRETS[name]
    head = template.split("{}")[0]
    for back in range(len(secret) + len(template) + 2):  # the slice ends at every position
        pad = "x " * ((MAX_TEXT_SLICE - len(head) - len(secret) + back) // 2)
        text = pad + template.replace("{}", secret) + " tail" * 400
        store = MemoryStore()
        fields: dict[str, Any] = {"actor": "a", "action": "x", "reason": "r", "data": {}, "at": 1}
        fields[field] = text
        RefusedAttempts(store, Counter()).record(TEAM, RUN, **fields)
        out = refused_items(store, str(RUN))[0].data[field]
        assert not longest_piece(secret, out), (back, out[-60:])


def test_a_secret_in_the_unclaimed_run_id_is_redacted() -> None:
    store = MemoryStore()
    RefusedAttempts(store, Counter()).record(
        TEAM, f"password=hunter2hunter2 {GH}", actor="a", action="x", reason="r", data={}, at=1
    )
    (item,) = refused_items(store, "unattributed")
    assert "hunter2" not in item.data["claimed_run"]
    assert GH not in item.data["claimed_run"]


def test_text_over_the_slice_is_cut_at_a_word_and_a_single_huge_word_is_dropped() -> None:
    store = MemoryStore()
    ra = RefusedAttempts(store, Counter())
    ra.record(TEAM, RUN, actor="a", action="w" * 10_000, reason="r", data={}, at=1)
    assert refused_items(store, str(RUN))[0].data["action"] == "...[truncated]"


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


def nested(depth: int) -> dict[str, Any]:
    root: dict[str, Any] = {}
    cur = root
    for _ in range(depth):
        cur["a"] = {}
        cur = cur["a"]
    return root


@pytest.mark.parametrize(
    ("what", "kw", "check"),
    [
        ("surrogate actor", {"actor": "\ud800 x"}, lambda d: d["actor"] == "? x"),
        ("surrogate action", {"action": "\ud800 x"}, lambda d: d["action"] == "? x"),
        ("surrogate reason", {"reason": "\ud800 x"}, lambda d: d["reason"] == "? x"),
        ("surrogate data", {"data": {"k": "\ud800"}}, lambda d: d["data"] == {"k": "?"}),
        ("depth 40", {"data": nested(40)}, lambda d: "[too large]" in json.dumps(d["data"])),
        ("depth 1100", {"data": nested(1100)}, lambda d: "[too large]" in json.dumps(d["data"])),
        (
            "NaN",
            {"data": {"x": float("nan")}},
            lambda d: d["data"] == {"x": "[number out of range]"},
        ),
        (
            "infinity",
            {"data": {"x": float("inf")}},
            lambda d: d["data"] == {"x": "[number out of range]"},
        ),
        (
            "huge int",
            {"data": {"x": 10**40}},
            lambda d: d["data"] == {"x": "[number out of range]"},
        ),
        ("int key", {"data": {1: "x"}}, lambda d: d["data"] == {"1": "x"}),
        ("tuple key", {"data": {(1, 2): "x"}}, lambda d: d["data"] == {"[tuple key]": "x"}),
        ("object", {"data": {"k": object()}}, lambda d: d["data"] == {"k": "[unstorable object]"}),
        ("bytes", {"data": {"k": GH.encode()}}, lambda d: d["data"] == {"k": "[40 bytes]"}),
        ("not a mapping", {"data": ["x"]}, lambda d: d["data"] == {"unstorable": True}),
        ("none data", {"data": None}, lambda d: d["data"] == {"unstorable": True}),
        ("float at", {"at": 1.5}, lambda d: d["at"] == 0),
        ("huge at", {"at": 10**30}, lambda d: d["at"] == 0),
    ],
)
def test_odd_inputs_still_leave_a_record(what: str, kw: dict[str, Any], check: Any) -> None:
    store, count = MemoryStore(), Counter()
    base = {"actor": "a", "action": "x", "reason": "r", "data": {}, "at": 1}
    RefusedAttempts(store, count).record(TEAM, RUN, **{**base, **kw})
    (item,) = refused_items(store, str(RUN))
    assert count.names == [], what
    assert check(item.data), (what, item.data)


def test_a_cyclic_value_still_leaves_a_record() -> None:
    cyc: dict[str, Any] = {}
    cyc["self"] = cyc
    store = MemoryStore()
    RefusedAttempts(store, Counter()).record(
        TEAM, RUN, actor="a", action="x", reason="r", data=cyc, at=1
    )
    assert len(refused_items(store, str(RUN))) == 1


def raising_first(exc: Exception, times: int = 1, *, then_commit: bool = False) -> MemoryStore:
    class Flaky(MemoryStore):
        calls = 0

        def transact(self, scope: Any, ops: Any) -> None:
            self.calls += 1
            if self.calls <= times:
                if then_commit:
                    super().transact(scope, ops)  # the write landed, the caller saw an error
                raise exc
            super().transact(scope, ops)

    return Flaky()


def test_a_store_that_refuses_the_record_as_invalid_gets_the_bounded_text_and_a_marker() -> None:
    store, count = raising_first(ValueError("item refused")), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="mallory", action="gate.decide", reason="not eligible", data={"k": 1}, at=3
    )
    items = refused_items(store, str(RUN))
    assert len(items) == 1, "the second write must have happened"
    item = items[0]
    assert item.data == {
        "run": str(RUN),
        "at": 3,
        "actor": "mallory",
        "action": "gate.decide",
        "reason": "not eligible",
        "data": {"unstorable": True},
    }
    assert store.calls == 2  # type: ignore[attr-defined]
    assert count.names == ["audit.refused_write_degraded"]  # the fallback is not silent


def test_a_transient_failure_is_retried_with_the_whole_record_not_a_marker() -> None:
    from sto.domain import TransientError

    store, count = raising_first(TransientError("throttled")), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={"evidence": "important"}, at=1
    )
    (item,) = refused_items(store, str(RUN))
    assert item.data["data"] == {"evidence": "important"}
    assert store.calls == 2  # type: ignore[attr-defined]
    assert count.names == []


def test_a_write_that_landed_before_the_error_is_not_written_twice() -> None:
    store, count = raising_first(RuntimeError("timeout after commit"), then_commit=True), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={"k": 1}, at=1
    )
    assert len(refused_items(store, str(RUN))) == 1
    assert count.names == []


def test_a_store_that_keeps_failing_is_counted_once_as_failed() -> None:
    store, count = raising_first(RuntimeError("down"), times=5), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={}, at=1
    )
    assert refused_items(store, str(RUN)) == []
    assert count.names == ["audit.refused_write_failed"]


def test_a_marker_write_that_also_fails_is_counted_as_failed() -> None:
    store, count = raising_first(ValueError("bad"), times=2), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={}, at=1
    )
    assert count.names == ["audit.refused_write_degraded", "audit.refused_write_failed"]


class Unprintable:
    def __str__(self) -> str:
        raise RuntimeError("no")


@pytest.mark.parametrize("field", ["actor", "action", "reason"])
@pytest.mark.parametrize("bad", [Unprintable(), 10**5000], ids=["str-raises", "5000-digit-int"])
def test_a_value_that_cannot_be_printed_still_leaves_a_record(field: str, bad: Any) -> None:
    store, count = MemoryStore(), Counter()
    fields: dict[str, Any] = {"actor": "a", "action": "x", "reason": "r", "data": {}, "at": 1}
    fields[field] = bad
    RefusedAttempts(store, count).record(TEAM, RUN, **fields)
    (item,) = refused_items(store, str(RUN))
    assert item.data[field].startswith("[unprintable")
    assert count.names == []


def test_a_wide_cycle_is_bounded_by_the_node_budget() -> None:
    cyc: dict[str, Any] = {}
    for i in range(20_000):
        cyc[f"k{i}"] = cyc
    store, count = MemoryStore(), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data=cyc, at=1
    )
    (item,) = refused_items(store, str(RUN))
    assert count.names == []
    assert len(json.dumps(item.data)) < 70_000


# --- keys are redacted whole, then clipped --------------------------------------------------------

KEY_SECRETS = {
    "name": ("{}_password", "hunter2hunter2"),
    "token-in-key": ("x{}", GH),
    "assign-in-key": ("password={}", "hunter2hunter2"),
    "bearer-in-key": ("Bearer {}", "abcdefghijklmn123"),
}


@pytest.mark.parametrize("name", KEY_SECRETS)
def test_a_secret_in_a_dict_key_survives_no_cut_position(name: str) -> None:
    template, secret = KEY_SECRETS[name]
    for pad in range(150, 260):  # the secret sits across the 200-character key bound
        key = (
            template.format("a" * pad)
            if name == "name"
            else "a" * pad + " " + template.format(secret)
        )
        store = MemoryStore()
        data = {key: secret} if name == "name" else {key: "v"}
        RefusedAttempts(store, Counter()).record(
            TEAM, RUN, actor="a", action="x", reason="r", data=data, at=1
        )
        (item,) = refused_items(store, str(RUN))
        stored = json.dumps(item.data["data"])
        assert not longest_piece(secret, stored), (pad, stored[-80:])


def test_long_keys_are_clipped_after_redaction_and_colliding_ones_get_a_counter() -> None:
    store = MemoryStore()
    data = {"k" * 300 + "1": 1, "k" * 300 + "2": 2}
    RefusedAttempts(store, Counter()).record(
        TEAM, RUN, actor="a", action="x", reason="r", data=data, at=1
    )
    (item,) = refused_items(store, str(RUN))
    keys = sorted(item.data["data"])
    assert len(keys) == 2
    assert all(len(k) < 230 for k in keys)
    assert sorted(item.data["data"].values()) == [1, 2]


def test_the_log_holds_a_read_only_view_of_the_store() -> None:
    log = StoreAuditLog(MemoryStore())
    view = log._view
    assert not hasattr(view, "transact")
    assert not hasattr(view, "put")
    assert not hasattr(view, "delete")


@pytest.mark.parametrize(
    "item",
    [{"x": 1}, {"seq": 0, "hash": "h"}, {"seq": -1, "hash": "h"},
     {"seq": True, "hash": "h"}, {"seq": 3, "hash": 5}, {"seq": 3, "hash": None}, {"seq": 3}],
)  # fmt: skip
def test_a_malformed_head_item_is_a_verification_error_not_a_keyerror(item: dict[str, Any]) -> None:
    store = MemoryStore()
    store.transact(TEAM, [Put(Key(f"RUN#{RUN}", "CHAIN"), item)])
    with pytest.raises(AuditVerificationError, match="malformed"):
        StoreAuditLog(store).head(TEAM, RUN)


def test_a_wellformed_head_is_read() -> None:
    store = MemoryStore()
    store.transact(TEAM, [Put(Key(f"RUN#{RUN}", "CHAIN"), {"seq": 1, "hash": "h"})])
    assert StoreAuditLog(store).head(TEAM, RUN) == ChainHead(1, "h")


def test_redaction_that_grows_the_data_past_the_bound_still_leaves_only_the_size() -> None:
    store = MemoryStore()
    data = {"k": "token=abcd " * 5_000}  # 55 KB as given, 85 KB once each value is replaced
    assert len(json.dumps(data)) < 64 * 1_024
    RefusedAttempts(store, Counter()).record(
        TEAM, RUN, actor="a", action="x", reason="r", data=data, at=1
    )
    (item,) = refused_items(store, str(RUN))
    assert set(item.data["data"]) == {"truncated", "bytes"}


def test_the_node_budget_bounds_the_work_on_a_wide_cycle_by_assertion() -> None:
    """Counts the keys visited and fails the moment it passes a limit far above the budget, so a
    missing budget fails here by assertion instead of running out of time or memory."""
    visited = [0]

    class Wide(dict[str, Any]):
        def items(self) -> Any:
            for i in range(20_000):
                visited[0] += 1
                assert visited[0] < 50_000, "no node budget: the walk is unbounded"
                yield f"k{i}", self

    store, count = MemoryStore(), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data=Wide(), at=1
    )
    assert visited[0] < 50_000
    assert len(refused_items(store, str(RUN))) == 1


# --- pass 4 ---------------------------------------------------------------------------------------

V = "Zq9xW7kP2mR4vT"


@pytest.mark.parametrize(
    ("key", "stored"),
    [
        (b"hunter2hunter2", "[bytes key]"),
        (("password", V), "[tuple key]"),
        (frozenset({V}), "[frozenset key]"),
        (12345, "12345"),
        (None, "None"),
        (1.5, "1.5"),
        (True, "True"),
    ],
)
def test_keys_that_are_not_text_or_numbers_are_markers_not_printed(key: Any, stored: str) -> None:
    store = MemoryStore()
    RefusedAttempts(store, Counter()).record(
        TEAM, RUN, actor="a", action="x", reason="r", data={key: "v"}, at=1
    )
    (item,) = refused_items(store, str(RUN))
    assert item.data["data"] == {stored: "v"}
    assert V not in json.dumps(item.data)
    assert "hunter2" not in json.dumps(item.data)


def test_a_key_object_whose_str_holds_a_secret_is_never_printed() -> None:
    class Key_:
        def __str__(self) -> str:
            return V

    store = MemoryStore()
    RefusedAttempts(store, Counter()).record(
        TEAM, RUN, actor="a", action="x", reason="r", data=cast(Any, {Key_(): "v"}), at=1
    )
    (item,) = refused_items(store, str(RUN))
    assert item.data["data"] == {"[Key_ key]": "v"}


def test_two_marker_keys_do_not_overwrite_each_other() -> None:
    store = MemoryStore()
    RefusedAttempts(store, Counter()).record(
        TEAM,
        RUN,
        actor="a",
        action="x",
        reason="r",
        data=cast(Any, {b"one": 1, b"two": 2, (1,): 3}),
        at=1,
    )
    (item,) = refused_items(store, str(RUN))
    assert sorted(item.data["data"].values()) == [1, 2, 3]
    assert len(item.data["data"]) == 3


class HostileMapping(dict[str, Any]):
    def items(self) -> Any:
        raise RuntimeError("boom")


class HostileList(list[Any]):
    def __iter__(self) -> Any:
        raise RuntimeError("boom")


class HostileInt(int):
    def __eq__(self, other: object) -> bool:
        raise RuntimeError("boom")

    __hash__ = int.__hash__


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (HostileMapping(), {"unstorable": True}),
        ({"x": HostileList()}, {"unstorable": True}),
        ({"x": HostileInt(1), "y": "kept"}, {"x": "[unstorable HostileInt]", "y": "kept"}),
    ],
    ids=["mapping", "list", "int"],
)
def test_hostile_data_keeps_the_record(data: Any, expected: dict[str, Any]) -> None:
    store, count = MemoryStore(), Counter()
    RefusedAttempts(store, count).record(
        TEAM, RUN, actor="a", action="x", reason="r", data=data, at=1
    )
    (item,) = refused_items(store, str(RUN))
    assert item.data["data"] == expected
    assert item.data["actor"] == "a"
    assert count.names == []


def _cycle() -> dict[str, Any]:
    cyc: dict[str, Any] = {}
    for i in range(20_000):
        cyc[f"k{i}"] = cyc
    return cyc


@pytest.mark.parametrize(
    "data",
    [
        {"l": list(range(20_000))},
        {f"k{i}": 0 for i in range(20_000)},
        {"l": [[1, 2, 3]] * 3_000},
        _cycle(),
    ],
    ids=["wide-list", "wide-dict", "list-of-lists", "wide-cycle"],
)
def test_a_cut_is_marked_in_the_stored_data(data: dict[str, Any]) -> None:
    from sto.audit.port import _MAX_NODES, _storable

    out = _storable(data, 0, [_MAX_NODES])
    assert "[too large]" in json.dumps(out)


def test_a_top_level_list_and_dict_over_the_item_cap_are_marked() -> None:
    from sto.audit.port import _MAX_NODES, _storable

    long_list = _storable(list(range(_MAX_NODES + 1)), 0, [_MAX_NODES])
    assert long_list[-1] == "[too large]"
    long_dict = _storable({f"k{i}": 0 for i in range(_MAX_NODES + 1)}, 0, [_MAX_NODES])
    assert "[too large]" in long_dict


def test_a_container_that_fits_the_budget_has_no_marker() -> None:
    from sto.audit.port import _MAX_NODES, _storable

    out = _storable({"l": list(range(4_000))}, 0, [_MAX_NODES])
    assert "[too large]" not in json.dumps(out)
    assert len(out["l"]) == 4_000
