"""Indexed queries (D3-10): one shared run against memory, SQLite and DynamoDB (on moto, so no
network and no Docker).

``IndexContract`` is the port's behaviour for promoted attributes and ``query_index``;
``HelperContract`` is ``sto.store.queries`` on top of it. Both run on every store, so each backend
gives the same answers. ``TestDynamoIndexes`` holds what only a real table shows: no scan on any
of these paths, top-level attributes, TTL.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from store_contract import A, B
from test_dynamodb import AUDIT_TABLE, MAIN_TABLE, Env, env  # noqa: F401  (env is a fixture)

from sto.domain.states import RunStatus
from sto.store import queries
from sto.store.memory import MemoryStore
from sto.store.ports import (
    AUDIT,
    MAX_ITEM_BYTES,
    PLATFORM,
    Absent,
    Check,
    ConditionFailedError,
    Exists,
    IndexedStore,
    Key,
    Put,
    TeamScope,
    attrs_size,
    encode_index_cursor,
    validate_ops,
)
from sto.store.sqlite import SqliteStore

pytestmark = pytest.mark.contract

RUN1 = Key("RUN#1", "META")


def keys(page: Any) -> list[tuple[str, str]]:
    return [(i.key.pk, i.key.sk) for i in page.items]


def walk(
    store: IndexedStore, scope: Any, index: str, pk: str, *, limit: int, **kw: Any
) -> list[Any]:
    """Every item of an index query, page by page."""
    out: list[Any] = []
    cursor = None
    for _ in range(1000):
        page = store.query_index(scope, index, pk, limit=limit, cursor=cursor, **kw)
        out += page.items
        cursor = page.cursor
        if cursor is None:
            return out
    raise AssertionError("cursor never ended")


class IndexContract:
    def test_promoted_attributes_round_trip_and_are_replaced_by_a_rewrite(
        self, store: IndexedStore
    ) -> None:
        store.put(A, RUN1, {"n": 1}, when=None)
        assert store.get(A, RUN1).attrs == {}  # type: ignore[union-attr]
        store.transact(A, [Put(RUN1, {"n": 2}, attrs={"gsi2pk": "RUNS#X", "gsi2sk": "t1"})])
        got = store.get(A, RUN1)
        assert got is not None
        assert got.attrs == {"gsi2pk": "RUNS#X", "gsi2sk": "t1"}
        # A Put replaces the item, so attributes it leaves out are gone from the index too.
        store.transact(A, [Put(RUN1, {"n": 3})])
        assert store.get(A, RUN1).attrs == {}  # type: ignore[union-attr]
        assert store.query_index(A, "gsi2", "RUNS#X").items == ()

    def test_delete_removes_the_index_entry(self, store: IndexedStore) -> None:
        store.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R", "gsi2sk": "t"})])
        assert len(store.query_index(A, "gsi2", "R").items) == 1
        store.delete(A, RUN1)
        assert store.query_index(A, "gsi2", "R").items == ()

    def test_a_moved_entry_is_found_under_its_new_key_only(self, store: IndexedStore) -> None:
        store.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R#OLD", "gsi2sk": "t"})])
        store.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R#NEW", "gsi2sk": "t"})])
        assert store.query_index(A, "gsi2", "R#OLD").items == ()
        (item,) = store.query_index(A, "gsi2", "R#NEW").items
        assert item.key == RUN1
        assert item.version == 2

    def test_index_order_prefix_and_direction(self, store: IndexedStore) -> None:
        for n, sk in enumerate(["2024-03", "2024-01", "2023-12", "2024-02"]):
            store.transact(
                A, [Put(Key(f"RUN#{n}", "META"), {"n": n}, attrs={"gsi2pk": "R", "gsi2sk": sk})]
            )
        order = ["RUN#2", "RUN#1", "RUN#3", "RUN#0"]
        assert [k[0] for k in keys(store.query_index(A, "gsi2", "R"))] == order
        desc = store.query_index(A, "gsi2", "R", descending=True)
        assert [k[0] for k in keys(desc)] == order[::-1]
        pre = store.query_index(A, "gsi2", "R", sk_prefix="2024-0")
        assert [k[0] for k in keys(pre)] == ["RUN#1", "RUN#3", "RUN#0"]
        assert store.query_index(A, "gsi3", "R").items == ()  # another index is another index

    def test_an_index_query_returns_data_version_and_attrs(self, store: IndexedStore) -> None:
        store.transact(A, [Put(RUN1, {"a": [1, {"b": 2}]}, attrs={"gsi4pk": "P", "gsi4sk": "s"})])
        (item,) = store.query_index(A, "gsi4", "P").items
        assert item.data == {"a": [1, {"b": 2}]}
        assert item.version == 1
        assert item.attrs == {"gsi4pk": "P", "gsi4sk": "s"}

    def test_the_team_root_partition_can_be_indexed(self, store: IndexedStore) -> None:
        root = Key("TEAM", "META")
        store.transact(A, [Put(root, {}, attrs={"gsi5pk": "X", "gsi5sk": "s"})])
        (item,) = store.query_index(A, "gsi5", "X").items
        assert item.key == root

    def test_teams_and_the_platform_never_see_each_others_entries(
        self, store: IndexedStore
    ) -> None:
        store.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R", "gsi2sk": "t"})])
        assert store.query_index(B, "gsi2", "R").items == ()
        org = Key("ORG", "RESOURCE#repo#x")
        store.transact(A, [Put(org, {}, attrs={"gsi5pk": "ORG#R", "gsi5sk": "s"}, scope=PLATFORM)])
        assert [i.key for i in store.query_index(PLATFORM, "gsi5", "ORG#R").items] == [org]
        assert store.query_index(A, "gsi5", "ORG#R").items == ()
        with pytest.raises(ValueError, match="platform"):
            store.query_index(PLATFORM, "gsi2", "R")  # team data needs a TeamScope

    def test_pagination_covers_everything_once_even_when_sort_keys_tie(
        self, store: IndexedStore
    ) -> None:
        for n in range(23):
            store.transact(
                A,
                [Put(Key(f"RUN#{n:02}", "META"), {}, attrs={"gsi2pk": "R", "gsi2sk": f"t{n % 3}"})],
            )
        for desc in (False, True):
            seen = [(i.key.pk) for i in walk(store, A, "gsi2", "R", limit=4, descending=desc)]
            assert len(seen) == 23
            assert len(set(seen)) == 23
            assert seen == [
                i.key.pk for i in walk(store, A, "gsi2", "R", limit=4, descending=desc)
            ]  # the same order every time

    def test_pagination_survives_writes_between_pages(self, store: IndexedStore) -> None:
        for n in range(6):
            store.transact(
                A,
                [Put(Key(f"RUN#{n}", "META"), {}, attrs={"gsi2pk": "R", "gsi2sk": f"t{n}"})],
            )
        first = store.query_index(A, "gsi2", "R", limit=2)
        assert [k[0] for k in keys(first)] == ["RUN#0", "RUN#1"]
        # Delete the last item seen, move an earlier one, add one before and one after the cursor.
        store.delete(A, Key("RUN#1", "META"))
        store.transact(A, [Put(Key("RUN#0", "META"), {}, attrs={"gsi2pk": "R", "gsi2sk": "t9"})])
        store.transact(A, [Put(Key("RUN#new0", "META"), {}, attrs={"gsi2pk": "R", "gsi2sk": "t"})])
        store.transact(
            A, [Put(Key("RUN#new1", "META"), {}, attrs={"gsi2pk": "R", "gsi2sk": "t55"})]
        )
        got: list[str] = []
        cursor = first.cursor
        while cursor is not None:
            page = store.query_index(A, "gsi2", "R", limit=2, cursor=cursor)
            got += [k[0] for k in keys(page)]
            cursor = page.cursor
        # Nothing after the cursor is skipped or repeated; "RUN#new0" sorts before it, so is not
        # shown; "RUN#0" moved past it and is shown once.
        assert got == ["RUN#2", "RUN#3", "RUN#4", "RUN#5", "RUN#new1", "RUN#0"]

    def test_a_cursor_is_bound_to_its_query(self, store: IndexedStore) -> None:
        for n in range(3):
            store.transact(
                A, [Put(Key(f"RUN#{n}", "META"), {}, attrs={"gsi2pk": "R", "gsi2sk": f"t{n}"})]
            )
        cursor = store.query_index(A, "gsi2", "R", limit=1).cursor
        assert cursor is not None
        for bad in (
            dict(index="gsi2", pk="S"),
            dict(index="gsi3", pk="R"),
            dict(index="gsi2", pk="R", sk_prefix="t"),
            dict(index="gsi2", pk="R", descending=True),
        ):
            with pytest.raises(ValueError, match="cursor"):
                store.query_index(A, cursor=cursor, **bad)
        with pytest.raises(ValueError, match="cursor"):
            store.query_index(B, "gsi2", "R", cursor=cursor)
        with pytest.raises(ValueError, match="cursor"):
            store.query_index(A, "gsi2", "R", cursor="not a cursor")
        # The same cursor is not valid on the table-key query either.
        with pytest.raises(ValueError, match="cursor"):
            store.query(A, "RUN#0", cursor=cursor)

    def test_bad_index_arguments_are_refused(self, store: IndexedStore) -> None:
        for bad in ("gsi6", "GSI1", "", "pk", "ttl"):
            with pytest.raises(ValueError, match="index"):
                store.query_index(A, bad, "R")
        with pytest.raises(ValueError, match="empty"):
            store.query_index(A, "gsi1", "")
        with pytest.raises(ValueError, match="limit"):
            store.query_index(A, "gsi1", "R", limit=0)

    def test_bad_promoted_attributes_are_refused_before_anything_is_written(
        self, store: IndexedStore
    ) -> None:
        bad: list[dict[str, Any]] = [
            {"gsi9pk": "a", "gsi9sk": "b"},  # not an index
            {"gsi1pk": "a"},  # a key half
            {"gsi1sk": "a"},
            {"gsi1pk": "", "gsi1sk": "a"},
            {"gsi1pk": "a", "gsi1sk": ""},
            {"gsi1pk": 1, "gsi1sk": "a"},
            {"gsi1pk": "a", "gsi1sk": "x" * 1025},
            {"gsi1pk": "x" * 2049, "gsi1sk": "a"},
            {"ttl": -1},
            {"ttl": True},
            {"ttl": 1.5},
            {"ttl": "5"},
            {"ttl": 10**40},
            {"d": "x"},  # may not shadow the data attribute
            {"pk": "x"},
        ]
        for attrs in bad:
            with pytest.raises((ValueError, TypeError)):
                Put(RUN1, {"n": 1}, attrs=attrs)
        with pytest.raises(ValueError, match="audit"):
            Put(Key("RUN#1", "1", AUDIT), {}, when=Absent(), attrs={"ttl": 5})
        with pytest.raises(ValueError, match="platform"):
            store.transact(
                A,
                [
                    Put(
                        Key("ORG", "x"),
                        {},
                        attrs={"gsi5pk": "NOT-PLATFORM", "gsi5sk": "s"},
                        scope=PLATFORM,
                    )
                ],
            )
        assert store.get(A, RUN1) is None

    def test_a_ttl_is_kept_and_may_be_zero(self, store: IndexedStore) -> None:
        store.transact(A, [Put(RUN1, {}, attrs={"ttl": 1_900_000_000})])
        assert store.get(A, RUN1).attrs == {"ttl": 1_900_000_000}  # type: ignore[union-attr]
        store.transact(A, [Put(RUN1, {}, attrs={"ttl": 0})])
        assert store.get(A, RUN1).attrs == {"ttl": 0}  # type: ignore[union-attr]

    def test_a_failed_condition_changes_no_index(self, store: IndexedStore) -> None:
        store.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R", "gsi2sk": "a"})])
        from sto.store.ports import ConditionFailedError

        with pytest.raises(ConditionFailedError):
            store.transact(A, [Put(RUN1, {}, when=Absent(), attrs={"gsi2pk": "R", "gsi2sk": "b"})])
        assert [i.attrs["gsi2sk"] for i in store.query_index(A, "gsi2", "R").items] == ["a"]

    def test_promoted_attributes_count_towards_the_item_size_on_every_store(
        self, store: IndexedStore
    ) -> None:
        attrs: dict[str, str | int] = {}
        for i in range(1, 6):
            attrs[f"gsi{i}pk"] = "P" * 2000
            attrs[f"gsi{i}sk"] = "S" * 1000
        # JSON plus keys is just under the limit; the 15 KB of attributes (and the team prefix on
        # five index keys) push it over, and the port says so, not DynamoDB.
        data = {"x": "y" * (400 * 1024 - 2000)}
        with pytest.raises(ValueError, match="item is"):
            store.transact(A, [Put(RUN1, data, attrs=attrs)])
        with pytest.raises(ValueError, match="item is"):
            store.transact(A, [Put(Key("RUN#2", "META"), data, attrs=attrs, scope=None)])
        assert store.get(A, RUN1) is None
        assert store.get(A, Key("RUN#2", "META")) is None

    def test_delete_then_put_again_with_the_same_index_keys(self, store: IndexedStore) -> None:
        attrs = {"gsi2pk": "R", "gsi2sk": "t"}
        store.transact(A, [Put(RUN1, {"n": 1}, attrs=attrs)])
        store.delete(A, RUN1)
        assert store.query_index(A, "gsi2", "R").items == ()
        store.transact(A, [Put(RUN1, {"n": 2}, attrs=attrs)])
        (item,) = store.query_index(A, "gsi2", "R").items
        assert item.data == {"n": 2}
        assert item.version == 1
        store.delete(A, RUN1)
        assert store.query_index(A, "gsi2", "R").items == ()

    def test_ttl_is_epoch_seconds_and_a_millisecond_value_is_refused(
        self, store: IndexedStore
    ) -> None:
        top = 10**11 - 1
        store.transact(A, [Put(RUN1, {}, attrs={"ttl": top})])
        assert store.get(A, RUN1).attrs == {"ttl": top}  # type: ignore[union-attr]
        for bad in (10**11, 1_893_456_000_000, 10**13):
            with pytest.raises(ValueError, match="milliseconds"):
                Put(RUN1, {}, attrs={"ttl": bad})

    def test_a_forged_cursor_with_an_empty_sort_key_is_refused(self, store: IndexedStore) -> None:
        store.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R", "gsi2sk": "t"})])
        for last in (("", "RUN#1", "META"), ("t", "RUN#1", "")):
            cursor = encode_index_cursor("TEAM#team-a", "gsi2", "R", "", False, last)
            with pytest.raises(ValueError, match="cursor"):
                store.query_index(A, "gsi2", "R", cursor=cursor)
        # An empty item pk is the team root, and is fine.
        ok = encode_index_cursor("TEAM#team-a", "gsi2", "R", "", False, ("t", "", "META"))
        assert [i.key for i in store.query_index(A, "gsi2", "R", cursor=ok).items] == [RUN1]


class HelperContract:
    """``sto.store.queries`` on any store."""

    def start(self, store: IndexedStore, n: int, *, source: str = "jira", ref: str = "T-1") -> None:
        queries.start_run(
            store,
            A,
            Key(f"RUN#{n}", "META"),
            {"id": n, "status": "QUEUED"},
            run_id=f"r{n}",
            status=RunStatus.QUEUED,
            updated_at=f"2024-01-0{n}",
            ticket=(source, ref),
        )

    def test_a_second_active_run_for_a_ticket_is_refused_and_writes_nothing(
        self, store: IndexedStore
    ) -> None:
        self.start(store, 1)
        with pytest.raises(queries.ActiveRunExistsError) as err:
            self.start(store, 2)
        assert err.value.run_id == "r1"
        assert store.get(A, Key("RUN#2", "META")) is None
        # Another ticket, and the same ticket in another team, are unaffected.
        self.start(store, 3, ref="T-2")
        queries.start_run(
            store, B, Key("RUN#9", "META"), {}, run_id="r9", status=RunStatus.QUEUED,
            updated_at="x", ticket=("jira", "T-1"),
        )  # fmt: skip

    def test_two_threads_racing_for_one_ticket_have_exactly_one_winner(
        self, store: IndexedStore
    ) -> None:
        wins: list[int] = []
        refused: list[int] = []
        barrier = threading.Barrier(8)

        def go(n: int) -> None:
            barrier.wait()
            try:
                self.start(store, n)
                wins.append(n)
            except queries.ActiveRunExistsError:
                refused.append(n)

        threads = [threading.Thread(target=go, args=(n,)) for n in range(1, 9)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(wins) == 1
        assert len(refused) == 7
        assert [i.key.pk for i in queries.runs_for_ticket(store, A, "jira", "T-1").items] == [
            f"RUN#{wins[0]}"
        ]

    def test_releasing_the_claim_allows_a_new_run_and_only_the_owner_can_release(
        self, store: IndexedStore
    ) -> None:
        self.start(store, 1)
        with pytest.raises(queries.ClaimHeldByAnotherRunError) as err:
            queries.release_ticket_ops(store, A, "jira", "T-1", run_id="someone-else")
        assert err.value.holder == "r1"
        with pytest.raises(queries.ActiveRunExistsError):
            self.start(store, 2)
        store.transact(A, queries.release_ticket_ops(store, A, "jira", "T-1", run_id="r1"))
        self.start(store, 2)

    def test_a_run_without_a_claim_can_still_reach_a_terminal_status(
        self, store: IndexedStore
    ) -> None:
        k = Key("RUN#1", "META")
        store.transact(
            A, [Put(k, {"status": "QUEUED"}, attrs=queries.run_attrs(RunStatus.QUEUED, "t", k))]
        )
        ops = queries.release_ticket_ops(store, A, "jira", "T-404", run_id="r1")
        store.transact(
            A,
            [
                Put(
                    k,
                    {"status": "DONE"},
                    attrs=queries.run_attrs(RunStatus.DONE, "t2", k, ticket=("jira", "T-404")),
                ),
                *ops,
            ],
        )
        assert store.get(A, k).data == {"status": "DONE"}  # type: ignore[union-attr]

    def test_a_release_planned_on_an_absent_claim_fails_if_the_claim_appears_first(
        self, store: IndexedStore
    ) -> None:
        ops = queries.release_ticket_ops(store, A, "jira", "T-1", run_id="r1")  # absent: a Check
        self.start(store, 2)  # another run claims the ticket before the release commits
        with pytest.raises(ConditionFailedError):
            store.transact(A, [Put(Key("RUN#1", "META"), {}), *ops])
        assert store.get(A, Key("RUN#1", "META")) is None
        assert queries.runs_for_ticket(store, A, "jira", "T-1").items != ()

    def test_a_release_planned_for_one_holder_cannot_delete_a_newer_claim(
        self, store: IndexedStore
    ) -> None:
        self.start(store, 1)
        ops = queries.release_ticket_ops(store, A, "jira", "T-1", run_id="r1")  # a versioned Delete
        self.end_without_releasing(store, 1, RunStatus.DONE)
        self.start(store, 2)  # takes the claim over before r1's release commits
        with pytest.raises(ConditionFailedError):
            store.transact(A, [Put(Key("RUN#7", "META"), {}), *ops])
        claim = store.get(A, Key("TICKET#jira#T-1", "ACTIVE"))
        assert claim is not None
        assert claim.data["run_id"] == "r2"
        assert store.get(A, Key("RUN#7", "META")) is None

    def end_without_releasing(self, store: IndexedStore, n: int, status: RunStatus) -> None:
        k = Key(f"RUN#{n}", "META")
        store.transact(
            A,
            [Put(k, {"id": n, "status": status.value}, attrs=queries.run_attrs(status, "t9", k))],
        )

    def test_a_claim_held_by_a_finished_run_is_taken_over_in_one_transaction(
        self, store: IndexedStore
    ) -> None:
        self.start(store, 1)
        self.end_without_releasing(store, 1, RunStatus.DONE)
        self.start(store, 2)  # the holder is terminal, so this takes the claim
        claim = store.get(A, Key("TICKET#jira#T-1", "ACTIVE"))
        assert claim is not None
        assert claim.data["run_id"] == "r2"
        assert claim.version == 2
        assert [i.key.pk for i in queries.runs_for_ticket(store, A, "jira", "T-1").items] == [
            "RUN#2"
        ]
        with pytest.raises(queries.ClaimHeldByAnotherRunError):  # the old run cannot release it
            queries.release_ticket_ops(store, A, "jira", "T-1", run_id="r1")
        with pytest.raises(queries.ActiveRunExistsError):  # and r2 is a live holder now
            self.start(store, 3)

    def test_a_claim_held_by_a_live_or_missing_run_is_never_taken_over(
        self, store: IndexedStore
    ) -> None:
        self.start(store, 1)  # QUEUED
        self.end_without_releasing(store, 1, RunStatus.RUNNING)
        with pytest.raises(queries.ActiveRunExistsError) as err:
            self.start(store, 2)
        assert err.value.run_id == "r1"
        store.delete(A, Key("RUN#1", "META"))  # holder's run item is gone: cannot show it ended
        with pytest.raises(queries.ActiveRunExistsError):
            self.start(store, 2)
        assert store.get(A, Key("RUN#2", "META")) is None

    def test_a_failed_takeover_writes_nothing(self, store: IndexedStore) -> None:
        self.start(store, 1)
        self.end_without_releasing(store, 1, RunStatus.DONE)
        self.start(store, 2)
        self.end_without_releasing(store, 2, RunStatus.DONE)
        # A start that takes the claim over but fails on another operation changes nothing.
        with pytest.raises(ConditionFailedError):
            queries.start_run(
                store, A, Key("RUN#3", "META"), {}, run_id="r3", status=RunStatus.QUEUED,
                updated_at="t", ticket=("jira", "T-1"),
                extra_ops=[Check(Key("NOPE", "1"), Exists())],
            )  # fmt: skip
        assert store.get(A, Key("RUN#3", "META")) is None
        claim = store.get(A, Key("TICKET#jira#T-1", "ACTIVE"))
        assert claim is not None
        assert claim.data["run_id"] == "r2"

    def test_racing_takeovers_have_exactly_one_winner(self, store: IndexedStore) -> None:
        self.start(store, 1)
        self.end_without_releasing(store, 1, RunStatus.DONE)
        wins: list[int] = []
        barrier = threading.Barrier(8)

        def go(n: int) -> None:
            barrier.wait()
            with contextlib.suppress(queries.ActiveRunExistsError):
                self.start(store, n)
                wins.append(n)

        threads = [threading.Thread(target=go, args=(n,)) for n in range(2, 10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(wins) == 1
        claim = store.get(A, Key("TICKET#jira#T-1", "ACTIVE"))
        assert claim is not None
        assert claim.data["run_id"] == f"r{wins[0]}"

    def test_a_terminal_run_leaves_the_ticket_index_but_stays_in_the_run_list(
        self, store: IndexedStore
    ) -> None:
        self.start(store, 1)
        store.transact(
            A,
            [
                Put(
                    Key("RUN#1", "META"),
                    {"id": 1},
                    attrs=queries.run_attrs(
                        RunStatus.DONE, "2024-02-01", Key("RUN#1", "META"), ticket=("jira", "T-1")
                    ),
                ),
                *queries.release_ticket_ops(store, A, "jira", "T-1", run_id="r1"),
            ],
        )
        assert queries.runs_for_ticket(store, A, "jira", "T-1").items == ()
        done = queries.list_runs(store, A, RunStatus.DONE)
        assert [i.key.pk for i in done.items] == ["RUN#1"]
        assert queries.list_runs(store, A, RunStatus.QUEUED).items == ()

    def test_run_lists_are_newest_first_by_status_and_page_stably(
        self, store: IndexedStore
    ) -> None:
        for n in range(1, 8):
            self.start(store, n, ref=f"T-{n}")
        seen: list[str] = []
        cursor = None
        while True:
            page = queries.list_runs(store, A, RunStatus.QUEUED, limit=3, cursor=cursor)
            seen += [i.key.pk for i in page.items]
            cursor = page.cursor
            if cursor is None:
                break
        assert seen == [f"RUN#{n}" for n in range(7, 0, -1)]
        assert queries.list_runs(store, B, RunStatus.QUEUED).items == ()

    def test_pr_lookup(self, store: IndexedStore) -> None:
        store.transact(
            A, [Put(RUN1, {}, attrs=queries.pr_attrs("org/repo", 7, "2024-01-01", RUN1))]
        )
        assert [i.key for i in queries.runs_for_pr(store, A, "org/repo", 7).items] == [RUN1]
        assert queries.runs_for_pr(store, A, "org/repo", 8).items == ()
        assert queries.runs_for_pr(store, B, "org/repo", 7).items == ()

    def test_my_approvals_merges_roles_in_order_and_pages_stably(self, store: IndexedStore) -> None:
        gates = [("qa", "2024-01-05"), ("dev", "2024-01-01"), ("qa", "2024-01-03"),
                 ("dev", "2024-01-04"), ("ops", "2024-01-02"), ("qa", "2024-01-06"),
                 ("dev", "2024-01-07")]  # fmt: skip
        for n, (role, at) in enumerate(gates):
            k = Key(f"RUN#{n}", "GATE#g#1")
            store.transact(
                A,
                [Put(k, {}, attrs=queries.gate_queue_attrs(role, at, k))],
            )
        everything = [i.key.pk for i in queries.my_approvals(store, A, ["qa", "dev"]).items]
        assert everything == ["RUN#1", "RUN#2", "RUN#3", "RUN#0", "RUN#5", "RUN#6"]  # no ops
        for size in (1, 2, 4):
            seen: list[str] = []
            cursor = None
            for _ in range(len(everything) + 2):  # a cursor that does not advance fails here
                page = queries.my_approvals(store, A, ["dev", "qa"], limit=size, cursor=cursor)
                assert len(page.items) <= size
                seen += [i.key.pk for i in page.items]
                cursor = page.cursor
                if cursor is None:
                    break
            else:
                pytest.fail(f"my_approvals did not finish in {len(everything) + 2} pages")
            assert seen == everything
        assert queries.my_approvals(store, A, []).items == ()
        assert queries.my_approvals(store, B, ["qa"]).items == ()

    def test_my_approvals_drops_a_gate_once_it_closes(self, store: IndexedStore) -> None:
        k = Key("RUN#1", "GATE#g#1")
        store.transact(A, [Put(k, {}, attrs=queries.gate_queue_attrs("qa", "2024-01-01", k))])
        assert len(queries.my_approvals(store, A, ["qa"]).items) == 1
        store.transact(A, [Put(k, {"status": "APPROVED"})])
        assert queries.my_approvals(store, A, ["qa"]).items == ()

    def test_my_approvals_rejects_a_cursor_for_other_roles(self, store: IndexedStore) -> None:
        for n in range(3):
            k = Key(f"RUN#{n}", "GATE#g#1")
            store.transact(A, [Put(k, {}, attrs=queries.gate_queue_attrs("qa", f"t{n}", k))])
        cursor = queries.my_approvals(store, A, ["qa"], limit=1).cursor
        assert cursor is not None
        with pytest.raises(ValueError, match="cursor"):  # replayed by another team
            queries.my_approvals(store, B, ["qa"], limit=1, cursor=cursor)
        with pytest.raises(ValueError, match="cursor"):
            queries.my_approvals(store, A, ["dev"], limit=1, cursor=cursor)
        with pytest.raises(ValueError, match="cursor"):
            queries.my_approvals(store, A, ["qa"], limit=1, cursor="junk")

    def test_resources_of_a_team(self, store: IndexedStore) -> None:
        for kind, rid, team in [("repo", "a", "t1"), ("jira", "P", "t1"), ("repo", "b", "t2")]:
            store.transact(
                A,
                [
                    Put(
                        Key("ORG", f"RESOURCE#{kind}#{rid}"),
                        {"team": team},
                        attrs=queries.resource_attrs(team, kind, rid),
                        scope=PLATFORM,
                    )
                ],
            )
        got = queries.resources_of_team(store, "t1")
        assert [i.key.sk for i in got.items] == ["RESOURCE#jira#P", "RESOURCE#repo#a"]
        assert [i.key.sk for i in queries.resources_of_team(store, "t2").items] == [
            "RESOURCE#repo#b"
        ]

    def test_entries_with_one_stamp_have_distinct_sort_keys_and_page_with_limit_one(
        self, store: IndexedStore
    ) -> None:
        keys_ = [Key(f"RUN#{n}", "GATE#g#1") for n in range(5)]
        for k in keys_:
            store.transact(A, [Put(k, {}, attrs=queries.gate_queue_attrs("qa", "same", k))])
        sks = [store.get(A, k).attrs["gsi1sk"] for k in keys_]  # type: ignore[union-attr]
        assert len(set(sks)) == 5
        seen: list[str] = []
        cursor = None
        for _ in range(7):
            page = queries.my_approvals(store, A, ["qa"], limit=1, cursor=cursor)
            seen += [i.key.pk for i in page.items]
            cursor = page.cursor
            if cursor is None:
                break
        else:
            pytest.fail("did not finish")
        assert seen == [f"RUN#{n}" for n in range(5)]
        # The same holds for the other indexes that can tie.
        r = [Key(f"RUN#{n}", "META") for n in range(3)]
        made = [
            queries.run_attrs(RunStatus.QUEUED, "t", k, ticket=("s", "r"), pr=("o/r", 1)) for k in r
        ]
        for name in ("gsi2sk", "gsi3sk", "gsi4sk"):
            assert len({m[name] for m in made}) == 3

    def test_key_parts_that_would_collide_are_refused(self, store: IndexedStore) -> None:
        with pytest.raises(ValueError, match="must"):
            queries.ticket_attrs("a#b", "c", "t", RUN1)
        with pytest.raises(ValueError, match="must"):
            queries.gate_queue_attrs("a#b", "t", RUN1)
        with pytest.raises(ValueError, match="must"):
            queries.pr_attrs("a#b", 1, "t", RUN1)
        with pytest.raises(ValueError, match="must"):
            queries.gate_queue_attrs("", "t", RUN1)
        with pytest.raises(ValueError, match="PR number"):
            queries.pr_attrs("r", 0, "t", RUN1)
        with pytest.raises(ValueError, match="must"):  # a stamp with '#' would blur the key
            queries.gate_queue_attrs("qa", "a#b", RUN1)

    def test_ttl_helper_gives_epoch_seconds(self, store: IndexedStore) -> None:
        from datetime import UTC, datetime

        assert queries.ttl_attrs(datetime(2030, 1, 1, tzinfo=UTC)) == {"ttl": 1893456000}
        with pytest.raises(ValueError, match="timezone"):
            queries.ttl_attrs(datetime(2030, 1, 1))


class TestMemoryIndexes(IndexContract, HelperContract):
    @pytest.fixture
    def store(self) -> IndexedStore:
        return MemoryStore()


class TestSqliteIndexes(IndexContract, HelperContract):
    @pytest.fixture
    def store(self, tmp_path: Path) -> Iterator[IndexedStore]:
        s = SqliteStore(tmp_path / "s.db")
        yield s
        s.close()


class TestDynamoIndexesOnMoto(IndexContract, HelperContract):
    @pytest.fixture
    def store(self, env: Env) -> IndexedStore:  # noqa: F811
        return env.store


class TestSqliteMigration:
    def test_a_file_made_before_indexes_gets_them(self, tmp_path: Path) -> None:
        import sqlite3

        path = tmp_path / "old.db"
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE items (partition TEXT NOT NULL, tbl TEXT NOT NULL, pk BLOB NOT NULL,"
            " sk BLOB NOT NULL, data TEXT NOT NULL, version INTEGER NOT NULL,"
            " PRIMARY KEY (partition, tbl, pk, sk)) WITHOUT ROWID"
        )
        conn.execute(
            "INSERT INTO items VALUES ('TEAM#team-a','main',?,?,'{\"n\":1}',3)",
            (b"RUN#1", b"META"),
        )
        conn.commit()
        conn.close()
        s = SqliteStore(path)
        try:
            got = s.get(A, RUN1)
            assert got is not None
            assert got.data == {"n": 1}
            assert got.attrs == {}
            s.transact(A, [Put(RUN1, {"n": 2}, attrs={"gsi2pk": "R", "gsi2sk": "t"})])
            assert [i.key for i in s.query_index(A, "gsi2", "R").items] == [RUN1]
        finally:
            s.close()


class TestSqliteSchemaVersion:
    def test_a_new_file_records_the_schema_version(self, tmp_path: Path) -> None:
        SqliteStore(tmp_path / "n.db").close()
        assert sqlite3.connect(tmp_path / "n.db").execute("PRAGMA user_version").fetchone() == (1,)

    def test_an_old_file_is_migrated_and_marked(self, tmp_path: Path) -> None:
        path = tmp_path / "old.db"
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE items (partition TEXT NOT NULL, tbl TEXT NOT NULL, pk BLOB NOT NULL,"
            " sk BLOB NOT NULL, data TEXT NOT NULL, version INTEGER NOT NULL,"
            " PRIMARY KEY (partition, tbl, pk, sk)) WITHOUT ROWID"
        )
        conn.commit()
        conn.close()
        SqliteStore(path).close()
        assert sqlite3.connect(path).execute("PRAGMA user_version").fetchone() == (1,)

    def test_a_file_from_newer_code_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "new.db"
        SqliteStore(path).close()
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA user_version=99")
        conn.close()
        with pytest.raises(RuntimeError, match="schema version 99"):
            SqliteStore(path)

    def test_delete_leaves_no_index_row_behind(self, tmp_path: Path) -> None:
        path = tmp_path / "d.db"
        s = SqliteStore(path)
        attrs = {"gsi2pk": "R", "gsi2sk": "t"}
        s.transact(A, [Put(RUN1, {}, attrs=attrs)])
        s.delete(A, RUN1)
        rows = sqlite3.connect(path).execute("SELECT count(*) FROM item_index").fetchone()
        assert rows == (0,)
        s.transact(A, [Put(RUN1, {}, attrs=attrs)])
        s.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R", "gsi2sk": "u"})])
        rows = sqlite3.connect(path).execute("SELECT count(*) FROM item_index").fetchone()
        assert rows == (1,)
        s.close()


class TestSizeAccountingInThePort:
    """The attributes, and the team prefix the store puts on index keys, are counted."""

    def test_the_team_prefix_counts_and_the_limit_is_exact(self) -> None:
        scope = TeamScope("team-a")
        attrs: dict[str, str | int] = {
            "gsi1pk": "P" * 2000,
            "gsi1sk": "S",
            "gsi2pk": "Q",
            "gsi2sk": "S",
        }
        base = len(json.dumps({"x": ""}, separators=(",", ":"))) + len("RUN#1") + len("META")
        fixed = base + attrs_size(attrs)  # no team prefix yet
        prefix = len("TEAM#team-a#") * 2  # two index pks
        data_len = MAX_ITEM_BYTES - fixed  # fills the limit exactly without the prefix
        Put(RUN1, {"x": "y" * data_len}, attrs=attrs)  # constructing it is fine
        with pytest.raises(ValueError, match="item is"):
            validate_ops(scope, [Put(RUN1, {"x": "y" * data_len}, attrs=attrs)])
        # Leaving room for exactly the prefix is accepted; one byte more is not.
        validate_ops(scope, [Put(RUN1, {"x": "y" * (data_len - prefix)}, attrs=attrs)])
        with pytest.raises(ValueError, match="item is"):
            validate_ops(scope, [Put(RUN1, {"x": "y" * (data_len - prefix + 1)}, attrs=attrs)])
        # Without attributes the same data is fine, so it is the attributes that count.
        validate_ops(scope, [Put(RUN1, {"x": "y" * data_len})])


class TestDynamoIndexes:
    """What a DynamoDB table does that the other stores do not."""

    def test_no_scan_on_any_indexed_path(self, env: Env) -> None:  # noqa: F811
        store = env.store
        g, r2 = Key("RUN#1", "GATE#g#1"), Key("RUN#2", "META")
        queries.start_run(
            store, A, RUN1, {}, run_id="r1", status=RunStatus.QUEUED, updated_at="2024-01-01",
            ticket=("jira", "T-1"),
        )  # fmt: skip
        store.transact(
            A,
            [
                Put(g, {}, attrs=queries.gate_queue_attrs("qa", "t", g)),
                Put(r2, {}, attrs=queries.pr_attrs("o/r", 3, "t", r2)),
                Put(
                    Key("ORG", "RESOURCE#repo#x"),
                    {},
                    attrs=queries.resource_attrs("team-a", "repo", "x"),
                    scope=PLATFORM,
                ),
            ],
        )
        env.client.calls.clear()
        queries.my_approvals(store, A, ["qa", "dev"], limit=1)
        queries.list_runs(store, A, RunStatus.QUEUED, limit=1)
        queries.runs_for_ticket(store, A, "jira", "T-1")
        queries.runs_for_pr(store, A, "o/r", 3)
        queries.resources_of_team(store, "team-a")
        names = [n for n, _ in env.client.calls]
        assert names
        assert set(names) == {"query"}
        for _, kw in env.client.calls:
            assert kw["IndexName"] in {"gsi1", "gsi2", "gsi3", "gsi4", "gsi5"}
            assert "ConsistentRead" not in kw or kw["ConsistentRead"] is False  # GSIs cannot
        assert {kw["IndexName"] for _, kw in env.client.calls} == {
            "gsi1", "gsi2", "gsi3", "gsi4", "gsi5",
        }  # fmt: skip

    def test_attributes_are_top_level_and_index_keys_carry_the_team(self, env: Env) -> None:  # noqa: F811
        env.store.transact(
            A,
            [
                Put(
                    RUN1,
                    {"status": "QUEUED"},
                    attrs={"gsi2pk": "RUNS#QUEUED", "gsi2sk": "t", "ttl": 1_900_000_000},
                ),
                Put(
                    Key("ORG", "RESOURCE#repo#x"),
                    {},
                    attrs={"gsi5pk": "ORG#TEAM#t1", "gsi5sk": "repo#x"},
                    scope=PLATFORM,
                ),
            ],
        )
        raw = {i["pk"]["S"]: i for i in env.raw_items()}
        run = raw["TEAM#team-a#RUN#1"]
        assert run["gsi2pk"] == {"S": "TEAM#team-a#RUNS#QUEUED"}
        assert run["gsi2sk"] == {"S": "t"}
        assert run["ttl"] == {"N": "1900000000"}
        assert set(run) == {"pk", "sk", "v", "d", "gsi2pk", "gsi2sk", "ttl"}
        assert raw["ORG"]["gsi5pk"] == {"S": "ORG#TEAM#t1"}  # platform keys stay as they are

    def test_a_rewrite_removes_attributes_it_leaves_out(self, env: Env) -> None:  # noqa: F811
        env.store.transact(A, [Put(RUN1, {}, attrs={"gsi2pk": "R", "gsi2sk": "t", "ttl": 5})])
        env.store.transact(A, [Put(RUN1, {"n": 2})])
        (raw,) = env.raw_items()
        assert set(raw) == {"pk", "sk", "v", "d"}

    def test_the_tables_have_the_five_indexes_and_a_ttl_on_ttl(self, env: Env) -> None:  # noqa: F811
        inner = env.client.inner
        main = inner.describe_table(TableName=MAIN_TABLE)["Table"]
        assert {g["IndexName"] for g in main["GlobalSecondaryIndexes"]} == {
            "gsi1", "gsi2", "gsi3", "gsi4", "gsi5",
        }  # fmt: skip
        for g in main["GlobalSecondaryIndexes"]:
            n = g["IndexName"]
            assert g["KeySchema"] == [
                {"AttributeName": f"{n}pk", "KeyType": "HASH"},
                {"AttributeName": f"{n}sk", "KeyType": "RANGE"},
            ]
            assert g["Projection"]["ProjectionType"] == "ALL"
        ttl = inner.describe_time_to_live(TableName=MAIN_TABLE)["TimeToLiveDescription"]
        assert ttl["AttributeName"] == "ttl"
        assert ttl["TimeToLiveStatus"] in ("ENABLED", "ENABLING")
        audit = inner.describe_table(TableName=AUDIT_TABLE)["Table"]
        assert not audit.get("GlobalSecondaryIndexes")

    def test_the_audit_table_takes_no_promoted_attributes(self, env: Env) -> None:  # noqa: F811
        with pytest.raises(ValueError, match="audit"):
            Put(Key("RUN#1", "1", AUDIT), {}, when=Absent(), attrs={"gsi1pk": "a", "gsi1sk": "b"})

    def test_create_tables_refuses_an_existing_table_without_the_indexes(self, env: Env) -> None:  # noqa: F811
        inner = env.client.inner
        inner.create_table(
            TableName="plain",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        from sto.store.dynamodb import create_tables

        with pytest.raises(RuntimeError, match="without the indexes"):
            create_tables(inner, main_table="plain", audit_table="plain-audit")

    def test_create_tables_can_run_twice(self, env: Env) -> None:  # noqa: F811
        from sto.store.dynamodb import create_tables

        create_tables(env.client.inner, main_table=MAIN_TABLE, audit_table=AUDIT_TABLE)

    def test_a_second_claim_is_refused_by_the_server_not_by_a_read(self, env: Env) -> None:  # noqa: F811
        queries.start_run(
            env.store, A, RUN1, {}, run_id="r1", status=RunStatus.QUEUED, updated_at="t",
            ticket=("jira", "T-1"),
        )  # fmt: skip
        env.client.calls.clear()
        with pytest.raises(queries.ActiveRunExistsError):
            queries.start_run(
                env.store, A, Key("RUN#2", "META"), {}, run_id="r2", status=RunStatus.QUEUED,
                updated_at="t", ticket=("jira", "T-1"),
            )  # fmt: skip
        sent = env.client.named("transact_write_items")
        assert len(sent) == 1  # one conditional transaction; no read-then-write window
