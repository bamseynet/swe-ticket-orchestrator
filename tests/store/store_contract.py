"""Reusable store contract suite (D1-01).

Subclass ``StoreContract`` in a ``Test*`` class and provide a ``store`` fixture returning a
fresh, empty ``Store``. The in-memory store does this in ``test_memory.py``; the SQLite store
(D1-12) and DynamoDB Local (D1-13 follow-ups) reuse it unchanged, so one set of semantics is
proved on every store.

The base class is not collected itself (its name does not start with ``Test``).
"""

from __future__ import annotations

import pytest

from sto.domain.ids import RunId
from sto.domain.models import Run
from sto.domain.serialize import from_wire, to_wire
from sto.store.ports import (
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
        assert store.query(A, "RUN#1") == ()

    # --- query --------------------------------------------------------------------------------

    def test_query_returns_one_partition_in_sort_key_order(self, store: Store) -> None:
        for sk in ("STEP#2", "GATE#1", "STEP#1"):
            store.put(A, Key("RUN#1", sk), {"sk": sk})
        store.put(A, Key("RUN#2", "STEP#1"), {"sk": "other run"})
        assert [i.key.sk for i in store.query(A, "RUN#1")] == ["GATE#1", "STEP#1", "STEP#2"]

    def test_query_prefix_and_limit(self, store: Store) -> None:
        for sk in ("GATE#1", "STEP#1", "STEP#2", "STEP#3"):
            store.put(A, Key("RUN#1", sk), {})
        assert [i.key.sk for i in store.query(A, "RUN#1", sk_prefix="STEP#")] == [
            "STEP#1",
            "STEP#2",
            "STEP#3",
        ]
        assert [i.key.sk for i in store.query(A, "RUN#1", sk_prefix="STEP#", limit=2)] == [
            "STEP#1",
            "STEP#2",
        ]

    def test_query_prefix_treats_wildcards_literally(self, store: Store) -> None:
        store.put(A, Key("P", "a%b"), {})
        store.put(A, Key("P", "axb"), {})
        store.put(A, Key("P", "a_b"), {})
        assert [i.key.sk for i in store.query(A, "P", sk_prefix="a%")] == ["a%b"]
        assert [i.key.sk for i in store.query(A, "P", sk_prefix="a_")] == ["a_b"]

    def test_query_of_an_empty_partition_is_empty(self, store: Store) -> None:
        assert store.query(A, "NOPE") == ()

    def test_query_limit_must_be_positive(self, store: Store) -> None:
        with pytest.raises(ValueError, match="limit"):
            store.query(A, "P", limit=0)

    # --- tenancy ------------------------------------------------------------------------------

    def test_teams_cannot_see_each_others_items(self, store: Store) -> None:
        store.put(A, RUN, {"owner": "a"})
        assert store.get(B, RUN) is None
        assert store.query(B, RUN.pk) == ()
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
