"""Local driver (D1-03): durable apply-and-feed-back loop, recovery from stored state only.

The kill tests run the driver in a child process on a real SQLite file and SIGKILL it at each
commit (just before it applies, and just after), then restart a fresh process on the same file.
A ledger file records every piece of *work* actually performed, so duplicated work shows up as a
repeated key, and the finished state must equal an uninterrupted run's.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import signal
import subprocess
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from sto.domain import (
    DecisionId,
    DecisionKind,
    FailureClass,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
    from_wire,
)
from sto.engine.commands import Finish, OpenGate, RunEffect, RunStep
from sto.engine.drivers.local import LocalDriver
from sto.engine.drivers.ports import command_key
from sto.engine.handlers.core import (
    EffectConfirmed,
    GateClosed,
    StepFailed,
    StepSucceeded,
)
from sto.engine.reducer import (
    LINEAR_V0,
    HandlerRegistry,
    NoHandlerError,
    OutOfOrderEventError,
    RunState,
)
from sto.store.memory import MemoryStore
from sto.store.ports import (
    Key,
    Store,
    TeamScope,
    TransactionConflictError,
)
from sto.store.sqlite import SqliteStore

RID = RunId.from_parts(1, bytes(10))
SCOPE = TeamScope("t1")
SUBJECT = Subject(
    patch_id="p1",
    ticket_revision="r1",
    head_sha="abc",
    evidence_digest="e1",
    attention_digest="a1",
)
THIS = Path(__file__).resolve()


def new_run() -> Run:
    return Run(id=RID, team="t1")


def approve(cmd: OpenGate) -> GateClosed:
    return GateClosed(
        cmd.run_id,
        cmd.name,
        cmd.round,
        DecisionKind.APPROVE,
        "alice",
        DecisionId.from_parts(cmd.round, bytes(10)),
        cmd.subject,
    )


class Worker:
    """Executor with a durable ledger. It is idempotent on the key, as the port requires:
    a key already in the ledger is not performed again, and the answer is a pure function of
    the command, so a re-run after a crash answers the same."""

    def __init__(self, ledger: Path, *, auto_approve: bool = True) -> None:
        self.ledger = ledger
        self.auto_approve = auto_approve

    def done(self) -> list[str]:
        return self.ledger.read_text().split() if self.ledger.exists() else []

    async def execute(self, key: str, command: object) -> Sequence[object]:
        if key not in self.done():
            with self.ledger.open("a") as f:
                f.write(key + "\n")
                f.flush()
                os.fsync(f.fileno())
        if isinstance(command, RunStep):
            return [StepSucceeded(StepKey(command.run_id, command.stage, command.visit), SUBJECT)]
        if isinstance(command, OpenGate):
            return [approve(command)] if self.auto_approve else []
        if isinstance(command, RunEffect):
            return [EffectConfirmed(command.run_id, command.type, command.visit, "merge1")]
        return []


class CountingStore:
    """Delegates to a store; ``hook(n, phase)`` runs around the n-th transaction (0-based)."""

    def __init__(self, inner: Store, hook: Any = None) -> None:
        self.inner, self.hook, self.commits = inner, hook, 0

    def get(self, scope: Any, key: Key) -> Any:
        return self.inner.get(scope, key)

    def query(self, scope: Any, pk: str, **kw: Any) -> Any:
        return self.inner.query(scope, pk, **kw)

    def transact(self, scope: Any, ops: Any) -> None:
        n, self.commits = self.commits, self.commits + 1
        if self.hook:
            self.hook(n, "before")
        self.inner.transact(scope, ops)
        if self.hook:
            self.hook(n, "after")

    def put(self, scope: Any, key: Key, data: Any, *, when: Any = None) -> None:
        raise AssertionError("the driver must commit through transact")

    def delete(self, scope: Any, key: Key, *, when: Any = None) -> None:
        raise AssertionError("the driver must commit through transact")


def drive(store: Store, worker: Worker, *, start: bool = True, **kw: Any) -> RunState:
    d = LocalDriver(store, SCOPE, LINEAR_V0, worker, **kw)

    async def go() -> RunState:
        if start:
            await d.start(new_run())
        return await d.run_until_idle(RID)

    return asyncio.run(go())


# --- the happy path ---------------------------------------------------------------------------


def test_runs_linear_workflow_to_done(tmp_path: Path) -> None:
    w = Worker(tmp_path / "ledger")
    rs = drive(MemoryStore(), w)
    assert rs.run.status is RunStatus.DONE
    assert len(w.done()) == len(set(w.done())) == 6  # 2 steps, 2 gates, 1 effect, finish


def test_state_is_persisted_in_the_store(tmp_path: Path) -> None:
    store = MemoryStore()
    rs = drive(store, Worker(tmp_path / "ledger"))
    item = store.get(SCOPE, Key(f"RUN#{RID}", "META"))
    assert item is not None
    assert from_wire(Run, item.data) == rs.run
    fresh = LocalDriver(store, SCOPE, LINEAR_V0, Worker(tmp_path / "ledger"))
    assert fresh.state(RID) == rs


def test_start_is_idempotent(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger")
    drive(store, w)
    before = w.done()
    assert drive(store, w).run.status is RunStatus.DONE  # start again, then idle
    assert w.done() == before


# --- a waiting gate stays waiting -------------------------------------------------------------


def test_waiting_gate_stays_waiting_and_is_not_reopened(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    first = drive(store, w)
    assert first.run.status is RunStatus.WAITING_HUMAN
    assert first.run.stage == "review_gate"
    for _ in range(3):  # restarts and idle polls change nothing
        again = drive(store, w, start=False)
        assert again == first
    assert [k for k in w.done() if k.startswith("gate:")] == [f"gate:{RID}:review_gate:1"]


def _gt(rs: RunState) -> Any:
    return LINEAR_V0.node(rs.run.stage).gate_type


def test_gate_decision_resumes_a_waiting_run(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    waiting = drive(store, w)
    d = LocalDriver(store, SCOPE, LINEAR_V0, w)
    cmd = OpenGate(RID, "review_gate", _gt(waiting), 1, SUBJECT)

    async def go() -> RunState:
        await d.submit(RID, approve(cmd))
        return await d.run_until_idle(RID)

    rs = asyncio.run(go())
    assert rs.run.stage == "qa_gate"
    assert rs.run.status is RunStatus.WAITING_HUMAN


def test_open_gate_key_is_run_name_round() -> None:
    gt = LINEAR_V0.node("review_gate").gate_type
    a = command_key(OpenGate(RID, "review_gate", gt, 1, SUBJECT), 7)  # type: ignore[arg-type]
    b = command_key(OpenGate(RID, "review_gate", gt, 1, SUBJECT), 99)  # type: ignore[arg-type]
    c = command_key(OpenGate(RID, "review_gate", gt, 2, SUBJECT), 7)  # type: ignore[arg-type]
    assert a == b != c


# --- stale events, unknown events -------------------------------------------------------------


def test_late_event_is_discarded_and_recorded(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    waiting = drive(store, w)
    d = LocalDriver(store, SCOPE, LINEAR_V0, w)
    late = StepSucceeded(StepKey(RID, "implement", 1, 1), SUBJECT)

    async def go() -> RunState:
        await d.submit(RID, late)
        return await d.run_until_idle(RID)

    assert asyncio.run(go()) == waiting
    assert [r["reason"] for r in d.rejected(RID)] == ["out_of_order"]


def test_no_handler_is_not_discarded_as_late(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    drive(store, w)

    # an empty registry has no handler for anything: the event must stay queued, not vanish
    d = LocalDriver(store, SCOPE, LINEAR_V0, w, registry=HandlerRegistry())

    async def go() -> None:
        await d.submit(RID, StepFailed(StepKey(RID, "x", 1), FailureClass.PERMANENT))
        await d.run_until_idle(RID)

    with pytest.raises(NoHandlerError):
        asyncio.run(go())
    assert d.rejected(RID) == []
    assert d.pending_events(RID) == 1


def test_out_of_order_is_the_only_discarded_error() -> None:
    assert issubclass(OutOfOrderEventError, Exception)
    assert not issubclass(NoHandlerError, OutOfOrderEventError)


# --- store conflicts --------------------------------------------------------------------------


def test_transaction_conflicts_are_retried_with_backoff(tmp_path: Path) -> None:
    sleeps: list[float] = []
    failures = {"left": 3}

    def flaky(n: int, phase: str) -> None:
        if phase == "before" and failures["left"] > 0 and n >= 2:
            failures["left"] -= 1
            raise TransactionConflictError("busy")

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    store = CountingStore(MemoryStore(), flaky)
    w = Worker(tmp_path / "ledger")
    rs = drive(store, w, sleep=fake_sleep)
    assert rs.run.status is RunStatus.DONE
    assert len(sleeps) == 3
    assert sleeps == sorted(sleeps)
    assert sleeps[0] < sleeps[-1]
    assert len(w.done()) == len(set(w.done()))


def test_persistent_conflict_gives_up(tmp_path: Path) -> None:
    def always(n: int, phase: str) -> None:
        if phase == "before" and n >= 1:
            raise TransactionConflictError("busy")

    async def no_sleep(_: float) -> None:
        return None

    with pytest.raises(TransactionConflictError):
        drive(CountingStore(MemoryStore(), always), Worker(tmp_path / "l"), sleep=no_sleep)


# --- real process kill on SQLite --------------------------------------------------------------


def _child(db: str, ledger: str, kill_at: int, phase: str, auto: bool) -> None:
    """Runs in a child process: drive the run on the SQLite file, killing itself at a commit."""

    def hook(n: int, ph: str) -> None:
        if n == kill_at and ph == phase:
            os.kill(os.getpid(), signal.SIGKILL)

    store = CountingStore(SqliteStore(db), hook)
    worker = Worker(Path(ledger), auto_approve=auto)
    rs = drive(store, worker)
    print(json.dumps({"status": rs.run.status.value, "stage": rs.run.stage}), flush=True)
    if not auto:
        os.kill(os.getpid(), signal.SIGKILL)  # die while the gate waits


def _spawn(db: Path, ledger: Path, kill_at: int, phase: str, auto: bool = True) -> Any:
    return subprocess.run(
        [sys.executable, str(THIS), "child", str(db), str(ledger), str(kill_at), phase, str(auto)],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )


# start, 6 events applied, 6 commands done. test_reference_run_commit_count pins it.
COMMITS = 13


def _dry_run(tmp_path: Path) -> tuple[int, list[str], RunState]:
    store = CountingStore(MemoryStore())
    w = Worker(tmp_path / "dry-ledger")
    rs = drive(store, w)
    return store.commits, w.done(), rs


@pytest.fixture(scope="module")
def reference(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, list[str], RunState]:
    return _dry_run(tmp_path_factory.mktemp("ref"))


def test_reference_run_commit_count(reference: tuple[int, list[str], RunState]) -> None:
    commits, work, rs = reference
    assert rs.run.status is RunStatus.DONE
    assert commits == COMMITS
    assert len(work) == 6


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("kill_at", range(COMMITS))
def test_kill_at_every_commit_finishes_with_no_duplicated_work(
    tmp_path: Path, kill_at: int, phase: str, reference: tuple[int, list[str], RunState]
) -> None:
    _, work, final = reference
    db, ledger = tmp_path / "s.db", tmp_path / "ledger"
    killed = _spawn(db, ledger, kill_at, phase)
    assert killed.returncode == -signal.SIGKILL, killed.stderr  # the kill really happened
    resumed = _spawn(db, ledger, -1, phase)
    assert resumed.returncode == 0, resumed.stderr
    assert json.loads(resumed.stdout)["status"] == RunStatus.DONE.value
    done = ledger.read_text().split()
    assert done == sorted(set(done), key=done.index), "a piece of work ran twice"
    assert sorted(done) == sorted(work)
    store = SqliteStore(db)
    rs = LocalDriver(store, SCOPE, LINEAR_V0, Worker(ledger)).state(RID)
    assert rs == final


def test_kill_while_gate_waits_then_restart_still_waits(tmp_path: Path) -> None:
    db, ledger = tmp_path / "s.db", tmp_path / "ledger"
    died = _spawn(db, ledger, -1, "before", auto=False)
    assert died.returncode == -signal.SIGKILL
    assert json.loads(died.stdout)["stage"] == "review_gate"
    again = _spawn(db, ledger, -1, "before", auto=False)  # fresh process, stored state only
    assert again.returncode == -signal.SIGKILL
    assert json.loads(again.stdout) == {
        "status": RunStatus.WAITING_HUMAN.value,
        "stage": "review_gate",
    }
    opened = [k for k in ledger.read_text().split() if k.startswith("gate:")]
    assert opened == [f"gate:{RID}:review_gate:1"]


def test_driver_loads_handlers_itself() -> None:
    """In a fresh interpreter nothing has called ``load_handlers``: building the driver must,
    or ``next`` refuses with ``HandlersNotLoadedError`` on the first event."""
    code = textwrap.dedent(
        """
        import asyncio
        from sto.domain import Run, RunId
        from sto.engine.drivers.local import LocalDriver
        from sto.engine.reducer import LINEAR_V0
        from sto.store.memory import MemoryStore
        from sto.store.ports import TeamScope

        class Idle:
            async def execute(self, key, command):
                return []

        rid = RunId.from_parts(1, bytes(10))
        d = LocalDriver(MemoryStore(), TeamScope("t"), LINEAR_V0, Idle())

        async def go():
            await d.start(Run(id=rid, team="t"))
            return await d.run_until_idle(rid)

        print(asyncio.run(go()).run.stage)
        """
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=dict(os.environ)
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "implement"


def test_wire_roundtrip_of_all_commands() -> None:
    from sto.engine.drivers.local import decode, encode

    gt = LINEAR_V0.node("review_gate").gate_type
    cmds = [
        RunStep(RID, "implement", 1, 1),
        OpenGate(RID, "review_gate", gt, 1, SUBJECT),  # type: ignore[arg-type]
        Finish(RID, RunStatus.DONE),
    ]
    for c in cmds:
        assert decode(json.loads(json.dumps(encode(c, "command"))), "command") == c
    assert dataclasses.is_dataclass(cmds[0])


if __name__ == "__main__" and sys.argv[1:2] == ["child"]:
    db_, ledger_, kill_, phase_, auto_ = sys.argv[2:7]
    _child(db_, ledger_, int(kill_), phase_, auto_ == "True")
