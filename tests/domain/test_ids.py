from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sto.domain import GateId, InvalidIdError, RunId, Ulid, to_wire

ms = st.integers(min_value=0, max_value=2**48 - 1)
rand = st.binary(min_size=10, max_size=10)


@given(ms, rand)
def test_ulid_roundtrip(t: int, r: bytes) -> None:
    u = Ulid.from_parts(t, r)
    assert len(str(u)) == 26
    assert Ulid.parse(str(u)) == u
    assert u.timestamp_ms == t


@given(ms, ms, rand)
def test_ulid_sorts_by_time(a: int, b: int, r: bytes) -> None:
    ua, ub = Ulid.from_parts(a, r), Ulid.from_parts(b, r)
    assert (a < b) == (str(ua) < str(ub)) or a == b


@pytest.mark.parametrize(
    "bad", ["", "abc", "U" * 26, "8" * 26, "0" * 25, "0" * 24 + "ß0", "0" * 25 + "é", "０" * 26]
)
def test_ulid_rejects_invalid(bad: str) -> None:
    with pytest.raises(InvalidIdError):
        Ulid.parse(bad)


def test_ids_are_distinct_types() -> None:
    v = Ulid.from_parts(1, bytes(10)).value
    assert RunId(v) != GateId(v)  # type: ignore[comparison-overlap]  # mypy forbids it too
    assert RunId(v) == RunId(v)
    assert hash(RunId(v)) == hash(RunId(v))


def test_new_ids_unique() -> None:
    assert RunId.new() != RunId.new()


@given(ms, rand)
def test_wire_form_is_the_ulid_string_and_roundtrips(t: int, r: bytes) -> None:
    rid = RunId.from_parts(t, r)
    assert to_wire(rid) == str(rid)
    assert RunId.parse(to_wire(rid)) == rid
    assert json.loads(json.dumps(to_wire({"run": rid, "ids": (rid,)}))) == {
        "run": str(rid),
        "ids": [str(rid)],
    }
