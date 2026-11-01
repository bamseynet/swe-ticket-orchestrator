"""The in-memory store passes the shared contract suite (D1-01)."""

from __future__ import annotations

import contextlib
import time

import pytest
from store_contract import StoreContract, race_claims

from sto.store import memory
from sto.store.memory import MemoryStore
from sto.store.ports import Store


class TestMemoryStore(StoreContract):
    @pytest.fixture
    def store(self) -> Store:
        return MemoryStore()


@pytest.fixture
def slow_conditions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Widen the window between checking conditions and applying writes, so a missing lock
    shows up on every run instead of once in a blue moon."""
    real = memory._holds

    def slow(*args: object) -> bool:
        result = real(*args)  # type: ignore[arg-type]
        time.sleep(0.0005)
        return result

    monkeypatch.setattr(memory, "_holds", slow)


@pytest.mark.usefixtures("slow_conditions")
def test_claims_stay_exclusive_even_when_checks_are_slow() -> None:
    assert race_claims(MemoryStore(), rounds=10) == [1] * 10


@pytest.mark.usefixtures("slow_conditions")
def test_the_race_test_can_fail_when_the_lock_is_removed() -> None:
    store = MemoryStore()
    store._lock = contextlib.nullcontext()  # type: ignore[assignment]
    assert max(race_claims(store, rounds=10)) > 1
