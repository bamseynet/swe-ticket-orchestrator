"""``record_with_audit`` (D3-19): the one way a non-gate change appends an audit entry.

It returns the caller's ops plus the chained audit ops, so the record and its entry commit in one
transaction, and the router that uses it never touches the audit seam itself.
"""

from __future__ import annotations

import pytest

from sto.domain import RunId
from sto.gates.hooks import ReadOnly, record_with_audit
from sto.gates.service import verify_audit_chain
from sto.store.memory import MemoryStore
from sto.store.ports import AUDIT, ConditionFailedError, Key, Put, TeamScope

TEAM = TeamScope("t")


def write(store: MemoryStore, run: RunId, n: int, *, action: str = "x.did") -> None:
    ops = record_with_audit(
        ReadOnly(store),
        TEAM,
        run,
        action=action,
        actor="iss|admin",
        data={"n": n, "token": "AKIAIOSFODNN7EXAMPLE"},
        at=1_000 + n,
        writes=[Put(Key(f"RUN#{run}", f"REC#{n}"), {"n": n})],
    )
    store.transact(TEAM, ops)


def test_the_record_and_its_entry_commit_together_and_the_chain_verifies() -> None:
    store, run = MemoryStore(), RunId.new()
    write(store, run, 1)
    write(store, run, 2)
    assert store.get(TEAM, Key(f"RUN#{run}", "REC#2")) is not None
    entries = [i.data for i in store.query(TEAM, f"RUN#{run}", table=AUDIT).items]
    assert [(e["seq"], e["action"], e["actor"], e["at"]) for e in entries] == [
        (1, "x.did", "iss|admin", 1_001),
        (2, "x.did", "iss|admin", 1_002),
    ]
    assert entries[0]["data"]["n"] == 1
    assert "AKIA" not in str(entries)  # the writer redacts, as for every entry
    assert verify_audit_chain(store, TEAM, run) == 2


def test_a_stale_chain_head_aborts_the_whole_transaction() -> None:
    store, run = MemoryStore(), RunId.new()
    write(store, run, 1)
    stale = record_with_audit(
        ReadOnly(store), TEAM, run, action="a", actor="iss|a", data={}, at=1, writes=[]
    )
    write(store, run, 2)  # the head moves
    with pytest.raises(ConditionFailedError):
        store.transact(TEAM, stale)
    assert verify_audit_chain(store, TEAM, run) == 2  # nothing of the stale call landed
