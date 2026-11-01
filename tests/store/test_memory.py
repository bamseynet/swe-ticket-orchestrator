"""The in-memory store passes the shared contract suite (D1-01)."""

from __future__ import annotations

import threading

import pytest
from store_contract import RUN, A, StoreContract

from sto.store.memory import MemoryStore
from sto.store.ports import ConditionFailedError, Put, Store, VersionIs


class TestMemoryStore(StoreContract):
    @pytest.fixture
    def store(self) -> Store:
        return MemoryStore()


def test_concurrent_claims_on_one_version_have_exactly_one_winner() -> None:
    store = MemoryStore()
    store.put(A, RUN, {"owner": None})
    wins: list[int] = []

    def claim(n: int) -> None:
        try:
            store.transact(A, [Put(RUN, {"owner": n}, when=VersionIs(1))])
            wins.append(n)
        except ConditionFailedError:
            pass

    threads = [threading.Thread(target=claim, args=(n,)) for n in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1
