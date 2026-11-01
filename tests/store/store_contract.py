"""Reusable store contract suite (D1-01).

Subclass ``StoreContract`` in a ``Test*`` class and provide a ``store`` fixture returning a
fresh, empty ``Store``. The in-memory store does this in ``test_memory.py``; the SQLite store
(D1-12) and DynamoDB Local (D1-13 follow-ups) reuse it unchanged, so one set of semantics is
proved on every store.

The base class is not collected itself (its name does not start with ``Test``).
"""

from __future__ import annotations

import sys
import threading
from enum import StrEnum

import pytest

from sto.domain.ids import RunId
from sto.domain.models import Run
from sto.domain.serialize import from_wire, to_wire
from sto.store.ports import (
    AUDIT,
    PLATFORM,
    Absent,
    Check,
    ConditionFailedError,
    Delete,
    Exists,
    FieldEquals,
    Key,
    Put,
    Store,
    TeamScope,
    VersionIs,
)


class Status(StrEnum):
    OPEN = "open"


def race_claims(store: Store, *, threads: int = 8, rounds: int = 40) -> list[int]:
    """Per round, how many of ``threads`` simultaneous claims on one version won. All threads
    start together (Barrier) with a tiny switch interval, to give a lockless store every chance
    to let two through. A correct store always yields 1."""
    counts: list[int] = []
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for r in range(rounds):
            key = Key("RACE", f"R{r}")
            store.put(A, key, {"owner": None})
            barrier = threading.Barrier(threads)
            wins: list[int] = []

            def claim(
                n: int, key: Key = key, wins: list[int] = wins, b: threading.Barrier = barrier
            ) -> None:
                b.wait()
                try:
                    store.transact(A, [Put(key, {"owner": n}, when=VersionIs(1))])
                    wins.append(n)
                except ConditionFailedError:
                    pass

            pool = [threading.Thread(target=claim, args=(n,)) for n in range(threads)]
            for t in pool:
                t.start()
            for t in pool:
                t.join()
            counts.append(len(wins))
    finally:
        sys.setswitchinterval(old)
    return counts


A = TeamScope("team-a")
B = TeamScope("team-b")
RUN = Key("RUN#1", "META")
GATE = Key("RUN#1", "GATE#g#1")


@pytest.mark.contract
class StoreContract:
    """Every store must pass these. ``store`` is supplied by the subclass."""

    # --- basic reads and writes -------------------------------------------------------------

    def test_get_missing_is_none(self, store: Store) -> None:
        assert store.get(A, RUN) is None

    def test_put_creates_version_one_and_get_returns_it(self, store: Store) -> None:
        store.put(A, RUN, {"status": "queued"})
        item = store.get(A, RUN)
        assert item is not None
        assert (item.key, item.data, item.version) == (RUN, {"status": "queued"}, 1)

    def test_each_write_bumps_the_version(self, store: Store) -> None:
        for expected in (1, 2, 3):
            store.put(A, RUN, {"n": expected})
            item = store.get(A, RUN)
            assert item is not None
            assert item.version == expected

    def test_delete_removes_the_item_and_missing_delete_is_a_no_op(self, store: Store) -> None:
        store.put(A, RUN, {"n": 1})
        store.delete(A, RUN)
        assert store.get(A, RUN) is None
        store.delete(A, RUN)

    def test_recreate_after_delete_restarts_at_version_one(self, store: Store) -> None:
        store.put(A, RUN, {"n": 1})
        store.put(A, RUN, {"n": 2})
        store.delete(A, RUN)
        store.put(A, RUN, {"n": 3}, when=Absent())
        item = store.get(A, RUN)
        assert item is not None
        assert item.version == 1

    def test_domain_record_round_trips_through_wire_form(self, store: Store) -> None:
        run = Run(id=RunId.new(), team="team-a", version=4, stage="plan")
        store.put(A, Key(f"RUN#{run.id}", "META"), to_wire(run))
        item = store.get(A, Key(f"RUN#{run.id}", "META"))
        assert item is not None
        assert from_wire(Run, item.data) == run

    # --- conditions ---------------------------------------------------------------------------

    def test_absent_condition_is_a_conditional_create(self, store: Store) -> None:
        store.put(A, RUN, {"n": 1}, when=Absent())
        with pytest.raises(ConditionFailedError):
            store.put(A, RUN, {"n": 2}, when=Absent())
        item = store.get(A, RUN)
        assert item is not None
        assert item.data == {"n": 1}
        assert item.version == 1

    def test_exists_condition_needs_an_item(self, store: Store) -> None:
        with pytest.raises(ConditionFailedError):
            store.put(A, RUN, {"n": 1}, when=Exists())
        assert store.get(A, RUN) is None
        store.put(A, RUN, {"n": 1})
        store.put(A, RUN, {"n": 2}, when=Exists())

    def test_version_counter_detects_a_conflicting_write(self, store: Store) -> None:
        store.put(A, RUN, {"n": 0})
        first = store.get(A, RUN)
        second = store.get(A, RUN)
        assert first is not None
        assert second is not None
        store.put(A, RUN, {"n": 1}, when=VersionIs(first.version))  # writer one wins
        with pytest.raises(ConditionFailedError):  # writer two read the same version: refused
            store.put(A, RUN, {"n": 2}, when=VersionIs(second.version))
        item = store.get(A, RUN)
        assert item is not None
        assert item.data == {"n": 1}
        assert item.version == 2

    def test_version_condition_on_a_missing_item_fails(self, store: Store) -> None:
        with pytest.raises(ConditionFailedError):
            store.put(A, RUN, {"n": 1}, when=VersionIs(1))

    def test_field_equals_guards_a_write(self, store: Store) -> None:
        store.put(A, GATE, {"status": "open"})
        store.put(A, GATE, {"status": "approved"}, when=FieldEquals("status", "open"))
        with pytest.raises(ConditionFailedError):  # a gate closes exactly once
            store.put(A, GATE, {"status": "rejected"}, when=FieldEquals("status", "open"))
        item = store.get(A, GATE)
        assert item is not None
        assert item.data == {"status": "approved"}

    def test_field_equals_fails_on_missing_item_and_missing_field(self, store: Store) -> None:
        with pytest.raises(ConditionFailedError):
            store.put(A, GATE, {"status": "x"}, when=FieldEquals("status", "open"))
        store.put(A, GATE, {"other": 1})
        with pytest.raises(ConditionFailedError):
            store.put(A, GATE, {"status": "x"}, when=FieldEquals("status", "open"))

    def test_conditional_delete(self, store: Store) -> None:
        store.put(A, RUN, {"n": 1})
        with pytest.raises(ConditionFailedError):
            store.delete(A, RUN, when=VersionIs(9))
        assert store.get(A, RUN) is not None
        store.delete(A, RUN, when=VersionIs(1))
        assert store.get(A, RUN) is None

    # --- transactions -------------------------------------------------------------------------

    def test_transaction_applies_every_write(self, store: Store) -> None:
        store.put(A, GATE, {"status": "open"})
        store.transact(
            A,
            [
                Put(RUN, {"status": "waiting"}, when=Absent()),
                Put(GATE, {"status": "approved"}, when=FieldEquals("status", "open")),
                Put(Key("RUN#1", "OUT#1"), {"signal": "wake"}, when=Absent()),
            ],
        )
        run, gate, out = (store.get(A, k) for k in (RUN, GATE, Key("RUN#1", "OUT#1")))
        assert run is not None
        assert run.data == {"status": "waiting"}
        assert gate is not None
        assert gate.data == {"status": "approved"}
        assert gate.version == 2
        assert out is not None
        assert out.data == {"signal": "wake"}

    def test_a_failed_condition_aborts_the_whole_transaction(self, store: Store) -> None:
        store.put(A, GATE, {"status": "approved"})
        store.put(A, Key("RUN#1", "OLD"), {"n": 1})
        with pytest.raises(ConditionFailedError) as caught:
            store.transact(
                A,
                [
                    Put(RUN, {"status": "waiting"}, when=Absent()),
                    Delete(Key("RUN#1", "OLD")),
                    Put(GATE, {"status": "rejected"}, when=FieldEquals("status", "open")),
                    Put(Key("RUN#1", "OUT#1"), {"signal": "wake"}),
                ],
            )
        assert caught.value.failed == (2,)
        assert store.get(A, RUN) is None  # earlier write rolled back
        assert store.get(A, Key("RUN#1", "OLD")) is not None  # earlier delete rolled back
        assert store.get(A, Key("RUN#1", "OUT#1")) is None  # later write never applied
        gate = store.get(A, GATE)
        assert gate is not None
        assert gate.data == {"status": "approved"}
        assert gate.version == 1

    def test_failure_reports_every_failed_operation(self, store: Store) -> None:
        store.put(A, RUN, {"n": 1})
        with pytest.raises(ConditionFailedError) as caught:
            store.transact(A, [Put(RUN, {"n": 2}, when=Absent()), Check(GATE, Exists())])
        assert caught.value.failed == (0, 1)

    def test_check_gates_a_transaction_without_writing(self, store: Store) -> None:
        store.put(A, RUN, {"status": "running"})
        store.transact(A, [Check(RUN, FieldEquals("status", "running")), Put(GATE, {"c": 1})])
        run = store.get(A, RUN)
        assert run is not None
        assert run.version == 1  # the checked item is untouched
        with pytest.raises(ConditionFailedError):  # e.g. Stop and an effect claim cannot both win
            store.transact(A, [Check(RUN, FieldEquals("status", "stopped")), Put(GATE, {"c": 2})])
        gate = store.get(A, GATE)
        assert gate is not None
        assert gate.data == {"c": 1}

    def test_two_claims_on_one_version_cannot_both_win(self, store: Store) -> None:
        store.put(A, RUN, {"owner": None})
        for owner, should_win in (("w1", True), ("w2", False)):
            ops = [Put(RUN, {"owner": owner}, when=VersionIs(1)), Put(Key("RUN#1", owner), {})]
            if should_win:
                store.transact(A, ops)
            else:
                with pytest.raises(ConditionFailedError):
                    store.transact(A, ops)
        assert store.get(A, Key("RUN#1", "w2")) is None

    def test_one_item_twice_in_a_transaction_is_refused_and_nothing_applies(
        self, store: Store
    ) -> None:
        with pytest.raises(ValueError, match="more than once"):
            store.transact(A, [Put(GATE, {"n": 1}), Put(RUN, {"n": 1}), Delete(GATE)])
        assert store.get(A, RUN) is None
        assert store.get(A, GATE) is None

    def test_empty_transaction_is_refused(self, store: Store) -> None:
        with pytest.raises(ValueError, match="at least one"):
            store.transact(A, [])

    def test_transaction_size_is_bounded_like_dynamodb(self, store: Store) -> None:
        ops = [Put(Key("RUN#1", f"S#{i}"), {"i": i}) for i in range(101)]
        with pytest.raises(ValueError, match="at most 100"):
            store.transact(A, ops)
        assert store.query(A, "RUN#1").items == ()

    # --- query --------------------------------------------------------------------------------

    def test_query_returns_one_partition_in_sort_key_order(self, store: Store) -> None:
        for sk in ("STEP#2", "GATE#1", "STEP#1"):
            store.put(A, Key("RUN#1", sk), {"sk": sk})
        store.put(A, Key("RUN#2", "STEP#1"), {"sk": "other run"})
        assert [i.key.sk for i in store.query(A, "RUN#1").items] == ["GATE#1", "STEP#1", "STEP#2"]

    def test_query_prefix_and_limit(self, store: Store) -> None:
        for sk in ("GATE#1", "STEP#1", "STEP#2", "STEP#3"):
            store.put(A, Key("RUN#1", sk), {})
        assert [i.key.sk for i in store.query(A, "RUN#1", sk_prefix="STEP#").items] == [
            "STEP#1",
            "STEP#2",
            "STEP#3",
        ]
        assert [i.key.sk for i in store.query(A, "RUN#1", sk_prefix="STEP#", limit=2).items] == [
            "STEP#1",
            "STEP#2",
        ]

    def test_query_prefix_treats_wildcards_literally(self, store: Store) -> None:
        store.put(A, Key("P", "a%b"), {})
        store.put(A, Key("P", "axb"), {})
        store.put(A, Key("P", "a_b"), {})
        assert [i.key.sk for i in store.query(A, "P", sk_prefix="a%").items] == ["a%b"]
        assert [i.key.sk for i in store.query(A, "P", sk_prefix="a_").items] == ["a_b"]

    def test_query_of_an_empty_partition_is_empty(self, store: Store) -> None:
        assert store.query(A, "NOPE").items == ()

    def test_query_limit_must_be_positive(self, store: Store) -> None:
        with pytest.raises(ValueError, match="limit"):
            store.query(A, "P", limit=0)

    # --- tenancy ------------------------------------------------------------------------------

    def test_teams_cannot_see_each_others_items(self, store: Store) -> None:
        store.put(A, RUN, {"owner": "a"})
        assert store.get(B, RUN) is None
        assert store.query(B, RUN.pk).items == ()
        store.put(B, RUN, {"owner": "b"}, when=Absent())  # same key, independent item
        a, b = store.get(A, RUN), store.get(B, RUN)
        assert a is not None
        assert a.data == {"owner": "a"}
        assert b is not None
        assert b.data == {"owner": "b"}

    def test_a_team_cannot_delete_or_condition_on_another_teams_item(self, store: Store) -> None:
        store.put(A, RUN, {"owner": "a"})
        store.delete(B, RUN)
        assert store.get(A, RUN) is not None
        with pytest.raises(ConditionFailedError):
            store.transact(B, [Check(RUN, Exists())])

    def test_every_operation_requires_a_team_scope(self, store: Store) -> None:
        bad: list[object] = [None, "team-a", {"team": "team-a"}]
        for scope in bad:
            with pytest.raises(TypeError, match="TeamScope"):
                store.get(scope, RUN)  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="TeamScope"):
                store.put(scope, RUN, {})  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="TeamScope"):
                store.delete(scope, RUN)  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="TeamScope"):
                store.query(scope, "P")  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="TeamScope"):
                store.transact(scope, [Put(RUN, {})])  # type: ignore[arg-type]

    def test_calls_without_a_scope_argument_cannot_be_made(self, store: Store) -> None:
        with pytest.raises(TypeError):
            store.get(RUN)  # type: ignore[call-arg,arg-type]
        with pytest.raises(TypeError):
            store.query("P")  # type: ignore[call-arg,arg-type]
        with pytest.raises(TypeError):
            store.transact([Put(RUN, {})])  # type: ignore[call-arg,arg-type]

    # --- value semantics ----------------------------------------------------------------------

    def test_stored_data_is_isolated_from_caller_mutation(self, store: Store) -> None:
        data = {"nested": {"xs": [1, 2]}}
        store.put(A, RUN, data)
        data["nested"]["xs"].append(3)
        item = store.get(A, RUN)
        assert item is not None
        assert item.data == {"nested": {"xs": [1, 2]}}
        item.data["nested"]["xs"].append(9)
        again = store.get(A, RUN)
        assert again is not None
        assert again.data == {"nested": {"xs": [1, 2]}}

    # --- review pass 1 ------------------------------------------------------------------------

    # scopes and tables

    def test_team_names_that_could_cross_partitions_are_refused(self, store: Store) -> None:
        for bad in ("a#b", "#", " a", "a ", "\ta"):
            with pytest.raises(ValueError, match="team"):
                TeamScope(bad)
        store.put(TeamScope("a"), Key("b#RUN#1", "META"), {"owner": "a"})
        assert store.get(TeamScope("ab"), Key("b#RUN#1", "META")) is None

    def test_platform_partitions_are_separate_from_every_team(self, store: Store) -> None:
        org, repo = Key("ORG", "BUD#2026-11"), Key("REPO#r", "SHA#abc")
        store.put(PLATFORM, org, {"spent": 1})
        store.put(PLATFORM, repo, {"run": "r1"}, when=Absent())
        assert store.get(A, org) is None
        assert store.get(PLATFORM, org) is not None
        store.put(A, org, {"spent": 99})  # a team's own item with the same key is independent
        got = store.get(PLATFORM, org)
        assert got is not None
        assert got.data == {"spent": 1}
        assert [i.key.sk for i in store.query(PLATFORM, "REPO#r").items] == ["SHA#abc"]
        assert store.query(A, "REPO#r").items == ()

    def test_platform_keys_cannot_impersonate_a_team_partition(self, store: Store) -> None:
        with pytest.raises(ValueError, match="TEAM#"):
            store.put(PLATFORM, Key("TEAM#team-a#RUN#1", "META"), {})

    def test_the_audit_table_is_separate_from_the_main_table(self, store: Store) -> None:
        store.put(A, Key("RUN#1", "1"), {"t": "main"})
        store.put(A, Key("RUN#1", "1", AUDIT), {"t": "audit"})
        main, audit = store.get(A, Key("RUN#1", "1")), store.get(A, Key("RUN#1", "1", AUDIT))
        assert main is not None
        assert audit is not None
        assert (main.data, audit.data) == ({"t": "main"}, {"t": "audit"})
        assert [i.data for i in store.query(A, "RUN#1", table=AUDIT).items] == [{"t": "audit"}]
        with pytest.raises(ValueError, match="table"):
            Key("p", "s", "other")

    def test_one_transaction_can_mix_team_platform_and_audit_items(self, store: Store) -> None:
        store.put(PLATFORM, Key("ORG", "SWITCH"), {"merge": "on"})
        store.put(A, GATE, {"status": "open"})
        store.transact(
            A,
            [
                Check(Key("ORG", "SWITCH"), FieldEquals("merge", "on"), scope=PLATFORM),
                Put(GATE, {"status": "approved"}, when=FieldEquals("status", "open")),
                Put(Key("RUN#1", "SEQ#1", AUDIT), {"event": "gate.approved"}, when=Absent()),
                Put(Key("REPO#r", "SHA#abc"), {"run": "1"}, when=Absent(), scope=PLATFORM),
            ],
        )
        assert store.get(PLATFORM, Key("REPO#r", "SHA#abc")) is not None
        assert store.get(A, Key("RUN#1", "SEQ#1", AUDIT)) is not None
        with pytest.raises(ConditionFailedError) as caught:  # a platform condition aborts all
            store.transact(
                A,
                [
                    Put(GATE, {"status": "late"}),
                    Check(Key("ORG", "SWITCH"), FieldEquals("merge", "off"), scope=PLATFORM),
                    Put(Key("RUN#1", "SEQ#2", AUDIT), {"event": "late"}),
                ],
            )
        assert caught.value.failed == (1,)
        gate = store.get(A, GATE)
        assert gate is not None
        assert gate.data == {"status": "approved"}
        assert store.get(A, Key("RUN#1", "SEQ#2", AUDIT)) is None

    def test_same_key_in_different_partitions_is_not_a_duplicate(self, store: Store) -> None:
        store.transact(A, [Put(RUN, {"o": "team"}), Put(RUN, {"o": "platform"}, scope=PLATFORM)])
        assert store.get(PLATFORM, RUN) is not None

    # data normalization

    def test_data_is_stored_as_plain_json(self, store: Store) -> None:
        store.put(A, RUN, {"t": (1, 2), "s": Status.OPEN, "f": 2.0, "h": 0.5, "n": {"x": [None]}})
        got = store.get(A, RUN)
        assert got is not None
        assert got.data == {"t": [1, 2], "s": "open", "f": 2, "h": 0.5, "n": {"x": [None]}}
        assert type(got.data["s"]) is str
        assert type(got.data["f"]) is int
        assert type(got.data["t"]) is list

    def test_data_that_is_not_json_is_refused_without_writing(self, store: Store) -> None:
        bad_values = ({"a": {1: "b"}}, {"a": {1, 2}}, {"a": float("nan")}, {"a": object()})
        for bad in (*bad_values, {"a": 10**40}):
            with pytest.raises(TypeError, match="JSON"):
                store.put(A, RUN, bad)
        assert store.get(A, RUN) is None

    def test_field_equals_matches_wire_values_strictly(self, store: Store) -> None:
        store.put(A, GATE, {"status": "open", "n": 1.0, "flag": True})
        store.transact(A, [Check(GATE, FieldEquals("status", Status.OPEN))])  # enum == wire value
        store.transact(A, [Check(GATE, FieldEquals("n", 1))])  # 1.0 is stored as 1
        store.transact(A, [Check(GATE, FieldEquals("n", 1.0))])  # type: ignore[arg-type]
        store.transact(A, [Check(GATE, FieldEquals("flag", True))])
        for name, value in (("n", True), ("flag", 1), ("n", "1")):
            with pytest.raises(ConditionFailedError):  # 1 is not True
                store.transact(A, [Check(GATE, FieldEquals(name, value))])

    def test_a_put_is_a_snapshot_so_later_mutation_cannot_half_commit(self, store: Store) -> None:
        data: dict[str, object] = {"x": 1}
        ops = [Put(Key("P", "1"), {"ok": 1}), Put(Key("P", "2"), data)]
        data["x"] = object()
        store.transact(A, ops)
        got = store.get(A, Key("P", "2"))
        assert got is not None
        assert got.data == {"x": 1}

    # keys and limits

    def test_operation_keys_must_be_keys(self, store: Store) -> None:
        with pytest.raises(TypeError, match="Key"):
            Put("notakey", {})  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="Key"):
            Delete(None)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="Key"):
            Check(("p", "s"), Exists())  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="Key"):
            store.get(A, "notakey")  # type: ignore[arg-type]
        assert store.query(A, "notakey").items == ()  # a later query still works

    def test_key_sizes_are_limited_like_dynamodb(self, store: Store) -> None:
        with pytest.raises(ValueError, match="pk"):
            Key("p" * 2049, "s")
        with pytest.raises(ValueError, match="sk"):
            Key("p", "s" * 1025)
        with pytest.raises(ValueError, match="pk"):
            Key("é" * 1025, "s")  # bytes, not characters
        Key("p" * 2048, "s" * 1024)
        with pytest.raises(ValueError, match="pk"):
            store.query(A, "p" * 3000)

    def test_an_oversize_item_is_refused_without_writing(self, store: Store) -> None:
        with pytest.raises(ValueError, match="item is"):
            store.put(A, RUN, {"blob": "x" * (5 * 1024 * 1024)})
        assert store.get(A, RUN) is None
        store.put(A, RUN, {"blob": "x" * (300 * 1024)})

    def test_a_transaction_of_exactly_100_operations_works(self, store: Store) -> None:
        store.transact(A, [Put(Key("BIG", f"S#{i:03}"), {"i": i}) for i in range(100)])
        assert len(store.query(A, "BIG").items) == 100

    def test_a_transaction_over_4_mb_is_refused_without_writing(self, store: Store) -> None:
        blob = {"blob": "x" * (390 * 1024)}
        store.transact(A, [Put(Key("BLOB", f"S#{i}"), blob) for i in range(10)])  # about 3.9 MB
        with pytest.raises(ValueError, match="transaction is"):
            store.transact(A, [Put(Key("BLOB2", f"S#{i}"), blob) for i in range(11)])
        assert store.query(A, "BLOB2").items == ()

    # pagination

    def test_pages_cover_everything_without_loss_or_repeats(self, store: Store) -> None:
        for i in range(25):
            store.put(A, Key("RUN#1", f"EVT#{i:03}"), {"i": i})
        store.put(A, Key("RUN#1", "GATE#1"), {})
        seen: list[str] = []
        cursor = None
        pages = 0
        while True:
            page = store.query(A, "RUN#1", sk_prefix="EVT#", limit=7, cursor=cursor)
            assert len(page.items) <= 7
            seen += [i.key.sk for i in page.items]
            pages += 1
            cursor = page.cursor
            if cursor is None:
                break
            assert pages < 20
        assert seen == [f"EVT#{i:03}" for i in range(25)]

    def test_paging_survives_writes_between_pages(self, store: Store) -> None:
        for i in (0, 2, 4, 6):
            store.put(A, Key("P", f"{i}"), {})
        first = store.query(A, "P", limit=2)
        assert [i.key.sk for i in first.items] == ["0", "2"]
        store.put(A, Key("P", "1"), {})  # behind the cursor: not seen, nothing repeats
        store.put(A, Key("P", "5"), {})  # ahead of the cursor: seen
        assert first.cursor is not None
        rest = store.query(A, "P", cursor=first.cursor)
        assert [i.key.sk for i in rest.items] == ["4", "5", "6"]
        assert rest.cursor is None

    def test_a_bad_cursor_is_refused(self, store: Store) -> None:
        with pytest.raises(ValueError, match="cursor"):
            store.query(A, "P", cursor="!!not a cursor!!")

    def test_query_results_do_not_alias_stored_data(self, store: Store) -> None:
        store.put(A, RUN, {"xs": [1]})
        store.query(A, RUN.pk).items[0].data["xs"].append(2)
        again = store.query(A, RUN.pk).items[0]
        assert again.data == {"xs": [1]}
        got = store.get(A, RUN)
        assert got is not None
        assert got.data == {"xs": [1]}

    # versions and concurrency

    def test_a_stale_version_matches_a_deleted_and_recreated_item(self, store: Store) -> None:
        """The ABA case, documented: ``Item.version`` restarts at 1 after a delete, so a writer
        holding ``VersionIs(1)`` from before cannot tell the item was replaced."""
        store.put(A, RUN, {"gen": 1})
        store.delete(A, RUN)
        store.put(A, RUN, {"gen": 2})
        store.put(A, RUN, {"gen": 3}, when=VersionIs(1))  # stale, yet it wins
        got = store.get(A, RUN)
        assert got is not None
        assert got.data == {"gen": 3}

    def test_simultaneous_claims_have_exactly_one_winner(self, store: Store) -> None:
        assert race_claims(store) == [1] * 40
