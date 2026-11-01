"""Value types of the store port (D1-01)."""

from __future__ import annotations

import pytest

from sto.domain.errors import PermanentError
from sto.store.ports import (
    PLATFORM,
    Absent,
    Check,
    ConditionFailedError,
    FieldEquals,
    Key,
    PlatformScope,
    Put,
    TeamScope,
    VersionIs,
    canonical_data,
)


def test_team_scope_needs_a_non_blank_team() -> None:
    assert TeamScope("t").team == "t"
    for bad in ("", "  "):
        with pytest.raises(ValueError, match="team"):
            TeamScope(bad)
    with pytest.raises(TypeError):
        TeamScope(None)  # type: ignore[arg-type]


def test_team_scope_is_hashable_and_comparable() -> None:
    assert TeamScope("t") == TeamScope("t")
    assert len({TeamScope("t"), TeamScope("t")}) == 1


def test_key_parts_must_be_non_empty_strings() -> None:
    for pk, sk in (("", "x"), ("x", ""), (1, "x"), ("x", None)):
        with pytest.raises((ValueError, TypeError)):
            Key(pk, sk)  # type: ignore[arg-type]


def test_put_data_must_be_plain_json() -> None:
    with pytest.raises(TypeError, match="JSON"):
        Put(Key("p", "s"), {"x": object()})
    with pytest.raises(TypeError, match="JSON"):
        Put(Key("p", "s"), {"x": {1, 2}})
    with pytest.raises(TypeError, match="object"):
        Put(Key("p", "s"), [1])  # type: ignore[arg-type]


def test_conditions_validate_their_arguments() -> None:
    with pytest.raises(ValueError, match="version"):
        VersionIs(0)
    with pytest.raises(ValueError, match="field"):
        FieldEquals("", 1)
    with pytest.raises(TypeError):
        FieldEquals("a", object())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Check(Key("p", "s"), None)  # type: ignore[arg-type]
    assert Absent() == Absent()


def test_condition_failure_is_a_permanent_error_naming_the_operations() -> None:
    err = ConditionFailedError((1, 3))
    assert isinstance(err, PermanentError)
    assert err.failed == (1, 3)
    assert "1" in str(err)
    assert "3" in str(err)


def test_canonical_data_is_a_private_plain_json_copy() -> None:
    source = {"a": [1, {"b": (2,)}]}
    out = canonical_data(source)
    assert out == {"a": [1, {"b": [2]}]}
    out["a"].append(3)
    assert source == {"a": [1, {"b": (2,)}]}


def test_platform_scope_is_explicit_and_distinct() -> None:
    assert PlatformScope() == PLATFORM
    assert not isinstance(PLATFORM, TeamScope)
    with pytest.raises(TypeError, match="PlatformScope"):
        Put(Key("p", "s"), {}, scope=TeamScope("t"))  # type: ignore[arg-type]
