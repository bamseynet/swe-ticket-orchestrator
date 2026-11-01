"""API v0 (D1-08): runs, events by cursor, gates and decisions, behind a dev token.

The app is driven through ASGI in one event loop (no sockets), over the real reducer, local
driver, gate service and effects service with the fake SCM. Every test runs under a deadline, and
every wait is a polled condition that fails with a message, so a stuck run reports what it was
waiting for instead of hanging CI.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Callable, Coroutine
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import MergeMethod, PrRef, PrSpec, RepoRef
from sto.api.app import DevAuthRefusedError, build_local, create_app, main
from sto.api.runtime import Runtime, scm_merge_factory
from sto.domain import DecisionKind, RunId, RunStatus, StepKey, Subject, Surface
from sto.effects.core import EffectExecutor
from sto.engine.commands import RunStep
from sto.engine.drivers.local import LocalDriver
from sto.engine.drivers.ports import Done, Outcome, StillRunning
from sto.engine.handlers.core import StepSucceeded
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import (
    ConditionFailedError,
    Key,
    Store,
    TeamScope,
    TransactionConflictError,
)
from sto.store.sqlite import SqliteStore

SCOPE = TeamScope("t1")
TOKEN = "dev-token"
REPO = RepoRef("acme", "app")
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def code_of(r: httpx.Response) -> object:
    """The error code of a response, or its status and text when it is not one of ours (a 500
    from an escaped exception then fails the assertion that compares it)."""
    try:
        return r.json()["error"]["code"]
    except (ValueError, KeyError, TypeError):
        return f"HTTP {r.status_code}: {r.text[:80]}"


def run[T](coro: Coroutine[Any, Any, T], timeout: float = 30) -> T:
    return asyncio.run(asyncio.wait_for(coro, timeout))


async def until(what: str, pred: Callable[[], Any], timeout: float = 5.0) -> Any:
    """Poll ``pred`` until it is truthy; fail with ``what`` and the last value if it never is."""
    loop = asyncio.get_running_loop()
    end, last = loop.time() + timeout, None
    while loop.time() < end:
        last = pred()
        if asyncio.iscoroutine(last):
            last = await last
        if last:
            return last
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}; last value: {last!r}")


class Steps:
    """Simulated step executor: every RunStep succeeds with the subject of the PR's head. A
    stage can be held (``hold[stage]`` is an Event the step waits for), made to poll
    (``slow``), or to fail (``boom``)."""

    def __init__(self, world: World) -> None:
        self.world = world
        self.hold: dict[str, asyncio.Event] = {}
        self.slow: set[str] = set()
        self.boom: Exception | None = None
        self.calls: list[str] = []
        self.queue: list[str] = []  # modes handed to new runs in order: "fail", "hold", "poll"
        self.modes: dict[RunId, str] = {}
        self.released = asyncio.Event()
        self.trace: list[tuple[str, str]] = []

    async def execute(self, key: str, command: object) -> Outcome:
        if not isinstance(command, RunStep):
            raise AssertionError(f"unexpected command {command!r}")
        self.calls.append(command.stage)
        self.trace.append((str(command.run_id)[-4:], command.stage))
        mode = self.modes.setdefault(command.run_id, self.queue.pop(0) if self.queue else "")
        if mode == "fail":
            raise RuntimeError("this run's step is broken")
        if mode == "poll":
            return StillRunning(3600.0, "poll")
        if mode == "hold":
            await self.released.wait()
        if self.boom is not None:
            raise self.boom
        if command.stage in self.slow:
            return StillRunning(3600.0, "slow")
        if command.stage in self.hold:
            await self.hold[command.stage].wait()
        subject = self.world.subject_for(command.run_id)
        return Done([StepSucceeded(StepKey(command.run_id, command.stage, command.visit), subject)])


class World:
    """One team's store, fake SCM, gate and effects services, and runtimes built over them."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.scm = FakeScm()
        self.scm.seed_branch(REPO, "main", "b0")
        self.prs: dict[RunId, PrRef] = {}
        self.default_pr = self.make_pr("sto/x", "abc")
        self.pr_queue: list[PrRef] = []
        self.gates = GateService(store)
        self.effects = EffectExecutor(store, SCOPE)
        self.steps = Steps(self)
        self.revision = "r1"

    def make_pr(self, branch: str, sha: str, repo: RepoRef = REPO) -> PrRef:
        if (repo, "main") not in self.scm._heads:  # a repo of its own: merges do not move REPO
            self.scm.seed_branch(repo, "main", "o0")
        base = "b0" if repo == REPO else "o0"
        self.scm.seed_branch(repo, branch, sha, parent=base)
        pr = PrRef.of(
            repo, self.scm.ensure_draft_pr(PrSpec(repo, branch, "main", "t", "b"), branch)
        )
        self.scm.mark_ready(pr, branch + "-ready")
        return pr

    def pr_for(self, run_id: RunId) -> PrRef:
        """A run owns the next queued PR the first time anything asks, else the default one."""
        if run_id not in self.prs:
            self.prs[run_id] = self.pr_queue.pop(0) if self.pr_queue else self.default_pr
        return self.prs[run_id]

    def subject_for(self, run_id: RunId) -> Subject:
        return Subject(
            patch_id="p1",
            ticket_revision=self.revision,
            head_sha=self.scm.pr_head(self.pr_for(run_id)),
            evidence_digest="e1",
            attention_digest="a1",
        )

    def live(self, cmd: Any) -> Subject:
        """The subject as it is now: head from the SCM, revision from the ticket."""
        subject: Subject = dataclasses.replace(
            cmd.subject,
            head_sha=self.scm.pr_head(self.pr_for(cmd.run_id)),
            ticket_revision=self.revision,
        )
        return subject

    def runtime(self, **kw: Any) -> Runtime:
        kw.setdefault("steps", self.steps)
        kw.setdefault("poll_interval", 0.01)
        kw.setdefault("lease_seconds", 1.0)
        kw.setdefault("backoff", 0.001)
        return Runtime(
            self.store,
            SCOPE,
            gates=self.gates,
            effects=self.effects,
            merges=scm_merge_factory(self.scm, self.store, SCOPE, self.pr_for, MergeMethod.SQUASH),
            live=kw.pop("live", self.live),
            **kw,
        )

    @contextlib.asynccontextmanager
    async def up(self, rt: Runtime | None = None) -> AsyncIterator[Api]:
        rt = rt or self.runtime()
        app = create_app(rt, token=TOKEN, mode="local")
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                yield Api(self, rt, app, c)

    async def land_merges(self) -> None:
        """Complete whatever merges the fake SCM has queued (a merge queue is asynchronous)."""
        done: set[int] = set()
        while True:
            for i, handle in enumerate(self.scm.merges()):
                if i not in done:
                    done.add(i)
                    self.scm.complete_merge(handle, f"m{i}")
            await asyncio.sleep(0.005)


@dataclasses.dataclass
class Api:
    world: World
    rt: Runtime
    app: FastAPI
    c: httpx.AsyncClient

    async def call(self, method: str, url: str, **kw: Any) -> httpx.Response:
        return await self.c.request(method, url, headers=AUTH, **kw)

    async def new_run(self, ticket: str = "DEMO-1") -> str:
        r = await self.call("POST", "/runs", json={"ticket": ticket})
        assert r.status_code == 202, r.text
        return str(r.json()["id"])

    async def run(self, run_id: str) -> dict[str, Any]:
        r = await self.call("GET", f"/runs/{run_id}")
        assert r.status_code == 200, r.text
        return dict(r.json())

    async def wait_for(self, run_id: str, status: str, stage: str | None = None) -> dict[str, Any]:
        async def seen() -> dict[str, Any] | None:
            got = await self.run(run_id)
            ok = got["status"] == status and (stage is None or got["stage"] == stage)
            return got if ok else None

        return dict(await until(f"run {run_id} to be {status} at {stage}", seen))

    async def gate(self, run_id: str, name: str) -> dict[str, Any]:
        """The newest round of a gate. The run's status changes a step before the gate is opened,
        so wait for it to exist."""

        async def found() -> dict[str, Any] | None:
            r = await self.call("GET", f"/runs/{run_id}/gates")
            assert r.status_code == 200, r.text
            mine = [g for g in r.json()["gates"] if g["name"] == name]
            return dict(mine[-1]) if mine else None

        return dict(await until(f"gate {name} of {run_id} to exist", found))

    async def decide(
        self,
        run_id: str,
        name: str,
        kind: str = "approve",
        *,
        digest: str | None = None,
        comment: str = "ok",
    ) -> httpx.Response:
        g = await self.gate(run_id, name)
        body = {"kind": kind, "subject_digest": digest or g["subject_digest"], "comment": comment}
        return await self.call(
            "POST", f"/runs/{run_id}/gates/{name}/{g['round']}/decisions", json=body
        )

    async def quiet(self) -> None:
        """Wait until nothing is driving (the last drive's release write has landed)."""
        await until("the drives to end", lambda: not self.rt.background_tasks())

    async def to_review_gate(self) -> str:
        run_id = await self.new_run()
        await self.wait_for(run_id, "WAITING_HUMAN", "review_gate")
        return run_id


# --- OpenAPI and auth ---------------------------------------------------------------------------


def test_openapi_is_generated_and_describes_the_routes() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            r = await api.c.get("/openapi.json")  # the spec itself needs no token
            assert r.status_code == 200
            spec = r.json()
            assert spec["openapi"].startswith("3.")
            paths = spec["paths"]
            for path, methods in {
                "/runs": {"get", "post"},
                "/runs/{run_id}": {"get"},
                "/runs/{run_id}/events": {"get"},
                "/runs/{run_id}/cancel": {"post"},
                "/runs/{run_id}/gates": {"get"},
                "/runs/{run_id}/gates/{name}/{round}/decisions": {"post"},
            }.items():
                assert methods <= set(paths[path]), path
            ids = [op["operationId"] for p in paths.values() for op in p.values()]
            assert len(ids) == len(set(ids)), "operation ids must be unique"
            decide = paths["/runs/{run_id}/gates/{name}/{round}/decisions"]["post"]
            assert {"202", "404", "409"} <= set(decide["responses"])
            assert "HTTPBearer" in str(spec["components"]["securitySchemes"])

    run(body())


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic dev-token"}]
)
def test_every_route_but_the_spec_needs_the_dev_token(headers: dict[str, str]) -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            for method, url in [
                ("GET", "/runs"),
                ("POST", "/runs"),
                ("GET", "/runs/x"),
                ("GET", "/runs/x/events"),
                ("POST", "/runs/x/cancel"),
                ("GET", "/runs/x/gates"),
                ("POST", "/runs/x/gates/g/1/decisions"),
            ]:
                r = await api.c.request(method, url, headers=headers)
                assert r.status_code == 401, (method, url, r.text)

    run(body())


def test_dev_auth_refuses_to_start_outside_local_mode() -> None:
    w = World(MemoryStore())
    for mode in ("cloud", "", "LOCAL", "dev"):
        with pytest.raises(DevAuthRefusedError):
            create_app(w.runtime(), token=TOKEN, mode=mode)
    with pytest.raises(DevAuthRefusedError):
        create_app(w.runtime(), token="", mode="local")


@pytest.mark.parametrize("mode", [None, "cloud", "prod"])
def test_the_local_stack_refuses_outside_local_mode(tmp_path: Path, mode: str | None) -> None:
    env = {"STO_DB": str(tmp_path / "x.db")} | ({} if mode is None else {"STO_MODE": mode})
    with pytest.raises(DevAuthRefusedError):
        build_local(env)
    assert not (tmp_path / "x.db").exists(), "refusing must happen before the store is opened"


def test_the_server_process_refuses_outside_local_mode(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("STO_")}
    env |= {"STO_MODE": "cloud", "STO_DB": str(tmp_path / "x.db"), "PYTHONPATH": "src"}
    done = subprocess.run(
        [sys.executable, "-m", "sto.api.app"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode != 0
    assert "local mode" in done.stderr
    assert not (tmp_path / "x.db").exists()


# --- runs, gates, decisions ---------------------------------------------------------------------


def test_a_run_goes_through_both_gates_to_a_merge() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            lander = asyncio.ensure_future(w.land_merges())
            try:
                run_id = await api.to_review_gate()
                got = await api.run(run_id)
                assert got["ticket"] == "DEMO-1"
                assert got["held"] is None
                gates = (await api.call("GET", f"/runs/{run_id}/gates")).json()["gates"]
                assert [(g["name"], g["round"], g["status"]) for g in gates] == [
                    ("review_gate", 1, "OPEN")
                ]
                assert gates[0]["head_sha"] == "abc"
                ok = await api.decide(run_id, "review_gate")
                assert ok.status_code == 202, ok.text
                assert ok.json()["gate"]["status"] == "APPROVED"
                await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
                assert (await api.decide(run_id, "qa_gate")).status_code == 202
                done = await api.wait_for(run_id, "DONE")
                assert done["stage"] == "merge"
                assert len(w.scm.merges()) == 1
            finally:
                lander.cancel()

    run(body())


def test_a_decision_returns_409_when_the_gate_is_closed() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            run_id = await api.to_review_gate()
            assert (await api.decide(run_id, "review_gate", "approve")).status_code == 202
            again = await api.decide(run_id, "review_gate", "reject")
            assert again.status_code == 409
            err = again.json()["error"]
            assert err["code"] == "gate_closed"
            assert err["closed_by"] == "dev"
            assert err["status"] == "APPROVED"
            assert err["gate"] == "review_gate"
            assert err["round"] == 1
            # PLAN 4.3 rule 5 / G3: after close the way to stop is Stop
            assert err.get("stop") == {"method": "POST", "href": f"/runs/{run_id}/cancel"}

    run(body())


def test_decision_refusals_have_their_own_status() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            run_id = await api.to_review_gate()
            g = await api.gate(run_id, "review_gate")
            base = f"/runs/{run_id}/gates"
            ok = {"kind": "approve", "subject_digest": g["subject_digest"]}
            missing = await api.call("POST", f"{base}/nope/1/decisions", json=ok)
            assert (missing.status_code, code_of(missing)) == (404, "gate_not_found")
            stale = await api.decide(run_id, "review_gate", digest="0" * 64)
            assert (stale.status_code, code_of(stale)) == (409, "stale_subject")
            bad = await api.call(
                "POST", f"{base}/review_gate/1/decisions", json={**ok, "kind": "x"}
            )
            assert bad.status_code == 422
            retest = await api.decide(run_id, "review_gate", "retest")
            assert (retest.status_code, code_of(retest)) == (
                422,
                "decision_not_allowed",
            )
            ghost = await api.call("GET", "/runs/no-such-run")
            assert ghost.status_code == 404
            assert (await api.gate(run_id, "review_gate"))["status"] == "OPEN"  # nothing closed it

    run(body())


def test_a_reject_ends_the_run_and_the_writer_is_never_called() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            assert (await api.decide(run_id, "review_gate", "reject")).status_code == 202
            await api.wait_for(run_id, "REJECTED")
            assert w.scm.merges() == []
            assert w.steps.calls == ["implement"]

    run(body())


def test_runs_are_listed_in_pages() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            ids = [await api.new_run(f"T-{i}") for i in range(3)]
            first = (await api.call("GET", "/runs", params={"limit": 2})).json()
            assert len(first["runs"]) == 2
            assert first["cursor"]
            rest = (
                await api.call("GET", "/runs", params={"limit": 2, "cursor": first["cursor"]})
            ).json()
            seen = [r["id"] for r in first["runs"] + rest["runs"]]
            assert sorted(seen) == sorted(ids)
            assert len(seen) == 3
            assert rest["cursor"] is None

    run(body())


def test_a_bad_runs_cursor_is_a_422_and_validation_errors_use_the_documented_shape() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            r = await api.call("GET", "/runs", params={"cursor": "junk"})
            assert (r.status_code, code_of(r)) == (422, "bad_cursor")
            bad = await api.call("POST", "/runs", json={"ticket": ["not", "text"]})
            assert bad.status_code == 422
            err = bad.json()["error"]
            assert err["code"] == "validation_error"
            assert err["fields"][0]["loc"][-1] == "ticket"

    run(body())


def test_cancel_is_refused_for_a_finished_or_stopping_run_and_unknown_run() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            run_id = await api.to_review_gate()
            assert (
                await api.decide(run_id, "review_gate", "reject", comment="no")
            ).status_code == 202
            await api.wait_for(run_id, "REJECTED")
            r = await api.call("POST", f"/runs/{run_id}/cancel")
            assert (r.status_code, code_of(r)) == (409, "run_finished")
            assert (await api.call("POST", "/runs/x/cancel")).status_code == 404

    run(body())


# --- events by cursor ---------------------------------------------------------------------------


def test_events_resume_from_a_cursor() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            url = f"/runs/{run_id}/events"
            everything = (await api.call("GET", url)).json()
            seqs = [e["seq"] for e in everything["events"]]
            assert len(seqs) >= 2
            assert seqs == sorted(seqs)
            assert [e["type"] for e in everything["events"]][0] == "run.started"

            one = (await api.call("GET", url, params={"limit": 1})).json()
            assert [e["seq"] for e in one["events"]] == seqs[:1]
            assert one["cursor"] == f"e{seqs[0]}"  # exactly the last seq seen, not a guess
            second = (
                await api.call("GET", url, params={"after": one["cursor"], "limit": 1})
            ).json()
            assert [e["seq"] for e in second["events"]] == seqs[1:2]  # no repeat, no skip
            rest = (await api.call("GET", url, params={"after": second["cursor"]})).json()
            assert [e["seq"] for e in rest["events"]] == seqs[2:]

            # At the end the cursor still resumes: nothing now, and exactly the new ones later.
            end = (await api.call("GET", url, params={"after": rest["cursor"]})).json()
            assert end["events"] == []
            assert end["cursor"] == rest["cursor"]
            await api.decide(run_id, "review_gate")
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            later = (await api.call("GET", url, params={"after": end["cursor"]})).json()
            assert [e["seq"] for e in later["events"]] == list(
                range(seqs[-1] + 1, seqs[-1] + 1 + len(later["events"]))
            )
            assert "gate.closed" in [e["type"] for e in later["events"]]

            for bad in ("junk", "-1", "e99999999999999999999"):
                r = await api.call("GET", url, params={"after": bad})
                assert r.status_code == 422, bad

    run(body())


# --- no request holds work open -----------------------------------------------------------------


def test_a_request_returns_while_the_work_it_started_is_still_running() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        w.steps.hold["qa"] = asyncio.Event()
        async with w.up() as api:
            run_id = await api.to_review_gate()
            r = await asyncio.wait_for(api.decide(run_id, "review_gate"), 5)
            assert r.status_code == 202
            await until("the qa step to be running", lambda: "qa" in w.steps.calls)
            assert (await api.run(run_id))["status"] == "RUNNING"  # the step is still held
            w.steps.hold["qa"].set()
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")

    run(body())


def test_a_stop_is_not_stuck_behind_a_long_retry_backoff() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        w.steps.slow.add("implement")  # StillRunning(3600): the driver would sleep an hour
        async with w.up() as api:
            run_id = await api.new_run()
            await until("the step to be polled", lambda: w.steps.calls == ["implement"])
            await asyncio.sleep(0.05)  # now asleep in the backoff
            r = await api.call("POST", f"/runs/{run_id}/cancel")
            assert r.status_code == 202
            await api.wait_for(run_id, "CANCELLED")

    run(body())


def test_a_stopped_runs_waiting_step_is_not_started() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        w.steps.slow.add("implement")
        async with w.up() as api:
            run_id = await api.new_run()
            await until("the step to be polled", lambda: w.steps.calls == ["implement"])
            await api.call("POST", f"/runs/{run_id}/cancel")
            await api.wait_for(run_id, "CANCELLED")
            await asyncio.sleep(0.1)
            assert w.steps.calls == ["implement"], "the writer must not run after a Stop"
            assert api.rt.driver.rejected(RunId.parse(run_id)) == []

    run(body())


def test_a_wake_up_only_reaches_the_run_it_was_for() -> None:
    """A submit for run B must not cut run A's backoff short (it would re-execute A early)."""

    async def body() -> None:
        w = World(MemoryStore())
        w.steps.slow.add("implement")
        async with w.up() as api:
            a = await api.new_run("A")
            await until("A polled once", lambda: w.steps.calls == ["implement"])
            await asyncio.sleep(0.05)
            b = await api.new_run("B")
            await until("B polled", lambda: len(w.steps.calls) == 2)
            await api.call("POST", f"/runs/{b}/cancel")
            await api.wait_for(b, "CANCELLED")
            await asyncio.sleep(0.1)
            assert w.steps.trace.count((str(a)[-4:], "implement")) == 1, w.steps.trace
            assert (await api.run(a))["status"] == "RUNNING"

    run(body())


def test_a_decision_that_arrives_after_the_drives_last_read_is_not_stranded() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        rt = w.runtime()
        async with w.up(rt) as api:
            run_id = await api.to_review_gate()
            real = rt.driver.run_until_idle
            fired: list[bool] = []

            async def late(rid: RunId) -> Any:
                result = await real(rid)
                if not fired:
                    fired.append(True)
                    # the drive has read its last state and is about to return
                    assert (await api.decide(str(rid), "review_gate")).status_code == 202
                return result

            rt.driver.run_until_idle = late  # type: ignore[method-assign,assignment]
            rt.kick(RunId.parse(run_id))
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            assert fired

    run(body())


def test_a_driver_exception_is_reported_not_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    async def body() -> None:
        w = World(MemoryStore())
        w.steps.boom = RuntimeError("step exploded")
        async with w.up() as api:
            with caplog.at_level(logging.ERROR, logger="sto.api"):
                run_id = await api.new_run()
                got = await until(
                    "the driver error to be reported",
                    lambda: api.rt.driver_error(RunId.parse(run_id)),
                )
            assert "step exploded" in got
            shown = await api.run(run_id)
            assert "step exploded" in shown["driver_error"]
            assert any(
                "step exploded" in str(r.exc_info) or "step exploded" in r.getMessage()
                for r in caplog.records
            )
            # fixing the cause and nudging the run clears the report
            w.steps.boom = None
            api.rt.kick(RunId.parse(run_id))
            await api.wait_for(run_id, "WAITING_HUMAN", "review_gate")
            rid = RunId.parse(run_id)
            await until("the report to clear", lambda: api.rt.driver_error(rid) is None)
            assert (await api.run(run_id))["driver_error"] is None

    run(body())


def test_the_runtime_keeps_a_reference_to_every_background_task() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        w.steps.hold["implement"] = asyncio.Event()
        async with w.up() as api:
            run_id = await api.new_run()
            await until("the step to start", lambda: w.steps.calls)
            assert api.rt.background_tasks(), "a running drive must be referenced"
            w.steps.hold["implement"].set()
            await api.wait_for(run_id, "WAITING_HUMAN", "review_gate")
            await until("tasks to be dropped when done", lambda: not api.rt.background_tasks())

    run(body())


# --- a crash between the decision and the submit ------------------------------------------------


def test_a_decision_recorded_but_never_submitted_is_delivered_on_restart(tmp_path: Path) -> None:
    async def body() -> None:
        w = World(SqliteStore(tmp_path / "s.db"))
        async with w.up() as api:
            run_id = await api.to_review_gate()
            g = await api.gate(run_id, "review_gate")
            # the process dies right after the gate service commits and before the submit
            w.gates.decide(
                SCOPE,
                run_id=RunId.parse(run_id),
                gate="review_gate",
                round=g["round"],
                kind=DecisionKind.APPROVE,
                actor="dev",
                surface=Surface.UI,
                subject_digest=g["subject_digest"],
            )
            assert (await api.run(run_id))["stage"] == "review_gate"
        async with w.up(w.runtime(owner="second")) as api2:  # a fresh process, same file
            await api2.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            kinds = [e["type"] for e in api2.rt.driver.timeline(RunId.parse(run_id))]
            assert kinds.count("gate.closed") == 1

    run(body())


def test_a_failed_submit_is_reported_and_a_retry_delivers_the_decision() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            real = api.rt.driver.submit
            calls = 0

            async def flaky(rid: RunId, event: object) -> None:
                nonlocal calls
                calls += 1
                if calls <= 1:
                    raise OSError("disk went away")
                await real(rid, event)

            api.rt.driver.submit = flaky  # type: ignore[method-assign,assignment]
            first = await api.decide(run_id, "review_gate")
            assert first.status_code == 503
            assert code_of(first) == "delivery_failed"
            assert first.json()["error"]["decision_recorded"] is True
            assert (await api.gate(run_id, "review_gate"))["status"] == "APPROVED"
            assert (await api.run(run_id))["stage"] == "review_gate"
            again = await api.decide(run_id, "review_gate")  # the retry: closed, and it heals
            assert again.status_code == 409
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            kinds = [e["type"] for e in api.rt.driver.timeline(RunId.parse(run_id))]
            assert kinds.count("gate.closed") == 1, "the decision must be delivered exactly once"

    run(body())


# --- the local stack: SQLite, handlers, resume --------------------------------------------------


def test_a_restart_keeps_a_waiting_gate_and_resumes_unfinished_runs(tmp_path: Path) -> None:
    async def body() -> None:
        db = SqliteStore(tmp_path / "s.db")
        w = World(db)
        w.steps.hold["implement"] = asyncio.Event()  # this run never leaves the first step
        async with w.up() as api:
            stuck = await api.new_run("STUCK")
            await until("the step to start", lambda: w.steps.calls)
        # first process gone; the second has no run id and finds the run from the store
        w2 = World(SqliteStore(tmp_path / "s.db"))
        w2.scm, w2.default_pr = w.scm, w.default_pr
        async with w2.up() as api2:
            waiting = await api2.wait_for(stuck, "WAITING_HUMAN", "review_gate")
            assert waiting["held"] is None

            async def opened() -> bool:  # the status changes a step before the gate is opened
                got = await api2.call("GET", f"/runs/{stuck}/gates")
                return bool(got.json()["gates"])

            await until("the gate to open", opened)
        async with w2.up(w2.runtime(owner="third")) as api3:
            assert (await api3.run(stuck))["stage"] == "review_gate"  # a waiting gate stays
            assert (await api3.gate(stuck, "review_gate"))["status"] == "OPEN"
            assert w2.steps.calls == ["implement"], "a waiting gate must not be re-driven"

    run(body())


def test_build_local_uses_a_sqlite_file_and_resumes_at_startup(tmp_path: Path) -> None:
    async def body() -> None:
        env = {"STO_MODE": "local", "STO_DB": str(tmp_path / "dev.db"), "STO_DEV_TOKEN": "tok"}
        app = build_local(env)
        rt: Runtime = app.state.runtime
        assert isinstance(rt.store, SqliteStore)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://t",
            ) as c,
        ):
            h = {"Authorization": "Bearer tok"}
            made = await c.post("/runs", json={"ticket": "DEMO-1"}, headers=h)
            run_id = made.json()["id"]
            await until(
                "review gate",
                lambda: rt.state(RunId.parse(run_id)).run.status is RunStatus.WAITING_HUMAN,
            )
        assert (tmp_path / "dev.db").exists()
        again = build_local(env)  # "restart"
        async with again.router.lifespan_context(again):
            rt2: Runtime = again.state.runtime
            assert rt2.state(RunId.parse(run_id)).run.stage == "review_gate"
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=again), base_url="http://t"
            ) as c:
                got = await c.get(f"/runs/{run_id}", headers={"Authorization": "Bearer tok"})
                assert got.json()["status"] == "WAITING_HUMAN"

    run(body())


def test_the_local_stack_runs_the_demo_through_both_gates_with_a_simulated_merge(
    tmp_path: Path,
) -> None:
    async def body() -> None:
        env = {
            "STO_MODE": "local",
            "STO_DB": str(tmp_path / "dev.db"),
            "STO_DEV_TOKEN": "tok",
            "STO_POLL_INTERVAL": "0.01",
        }
        app = build_local(env)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                h = {"Authorization": "Bearer tok"}

                async def call(method: str, url: str, **kw: Any) -> httpx.Response:
                    return await c.request(method, url, headers=h, **kw)

                run_id = (await call("POST", "/runs", json={"ticket": "DEMO-1"})).json()["id"]
                for gate in ("review_gate", "qa_gate"):

                    async def open_gate(gate: str = gate) -> dict[str, Any] | None:
                        got = (await call("GET", f"/runs/{run_id}/gates")).json()["gates"]
                        mine = [g for g in got if g["name"] == gate and g["status"] == "OPEN"]
                        return dict(mine[0]) if mine else None

                    g = await until(f"{gate} to be open", open_gate)
                    url = f"/runs/{run_id}/gates/{gate}/{g['round']}/decisions"
                    body = {"kind": "approve", "subject_digest": g["subject_digest"]}
                    assert (await call("POST", url, json=body)).status_code == 202
                done = await until(
                    "the run to be DONE",
                    lambda: (
                        app.state.runtime.state(RunId.parse(run_id)).run.status is RunStatus.DONE
                    ),
                )
                assert done

    run(body())


def test_the_server_will_not_bind_beyond_loopback_with_the_default_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("STO_MODE", "local")
    monkeypatch.setenv("STO_DB", str(tmp_path / "x.db"))
    monkeypatch.delenv("STO_DEV_TOKEN", raising=False)
    assert main(["--host", "0.0.0.0"]) == 2  # noqa: S104
    assert "STO_DEV_TOKEN" in capsys.readouterr().err
    assert not (tmp_path / "x.db").exists()


def test_startup_loads_the_handler_registries_before_the_driver_decodes_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sto.api.runtime as runtime_module

    order: list[str] = []
    monkeypatch.setattr(runtime_module, "load_handlers", lambda: order.append("load_handlers"))
    real_init = LocalDriver.__init__

    def init(self: LocalDriver, *a: Any, **k: Any) -> None:
        order.append("driver")
        real_init(self, *a, **k)

    monkeypatch.setattr(LocalDriver, "__init__", init)
    World(MemoryStore()).runtime()
    assert order[:2] == ["load_handlers", "driver"]


# --- the merge: dispatcher from the effect, live subject read fresh -----------------------------


def test_each_run_merges_its_own_pr_through_one_dispatcher() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        other = w.make_pr("sto/y", "def", RepoRef("acme", "other"))
        w.pr_queue = [w.default_pr, other]
        async with w.up() as api:
            lander = asyncio.ensure_future(w.land_merges())
            try:
                ids = [await api.to_review_gate(), await api.to_review_gate()]
                for run_id in ids:
                    await api.decide(run_id, "review_gate")
                for run_id in ids:
                    await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
                    await api.decide(run_id, "qa_gate")
                for run_id in ids:
                    await api.wait_for(run_id, "DONE")
                merged = {h.pr for h in w.scm.merges()}
                assert merged == {w.default_pr, other}, "each run merges the PR it owns"
            finally:
                lander.cancel()

    run(body())


def test_live_is_read_afresh_when_the_merge_is_claimed() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        reads: list[str] = []

        def live(cmd: Any) -> Subject:
            got = w.live(cmd)
            reads.append(str(got.head_sha))
            return got

        async with w.up(w.runtime(live=live)) as api:
            lander = asyncio.ensure_future(w.land_merges())
            try:
                run_id = await api.to_review_gate()
                await api.decide(run_id, "review_gate")
                await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
                assert reads == [], "live must not be read before a write can be claimed"
                # the branch moves after both approvals are about to exist
                w.scm.seed_branch(REPO, "sto/x", "moved", parent="abc")
                await api.decide(run_id, "qa_gate")
                blocked = await api.wait_for(run_id, "BLOCKED")
                assert blocked["blocked_reason"] == "effect_failed"
                assert reads == ["moved"], "the claim must see the head as it is now"
                assert w.scm.merges() == [], "a moved head must not be merged"
            finally:
                lander.cancel()

    run(body())


# --- store conflicts ----------------------------------------------------------------------------


class Conflicting:
    """Store wrapper: the first ``n`` writes to the API's own index raise a conflict."""

    def __init__(self, inner: Store, n: int) -> None:
        self.inner, self.n, self.seen = inner, n, 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def put(self, scope: Any, key: Key, data: Any, *, when: Any = None) -> None:
        if key.pk == "RUNS_API" and self.seen < self.n:
            self.seen += 1
            raise TransactionConflictError("busy")
        self.inner.put(scope, key, data, when=when)


@pytest.mark.parametrize(("conflicts", "status"), [(2, 202), (50, 503)])
def test_transaction_conflicts_are_retried_with_backoff(conflicts: int, status: int) -> None:
    async def body() -> None:
        sleeps: list[float] = []

        async def nap(s: float) -> None:
            sleeps.append(s)

        store = Conflicting(MemoryStore(), conflicts)
        w = World(store)
        async with w.up(w.runtime(api_sleep=nap)) as api:
            r = await api.call("POST", "/runs", json={"ticket": "T"})
            assert r.status_code == status, r.text
            if status == 202:
                assert store.seen == 2
                assert len(sleeps) == 2
                assert sleeps[1] > sleeps[0] > 0, "retries must back off"
            else:
                assert code_of(r) == "store_conflict"
                assert r.headers["retry-after"]
                assert 1 < len(sleeps) <= 10

    run(body())


def test_the_runtime_drives_only_through_run_until_idle() -> None:
    """The public ``step`` skips the per-run guard: only the driver's own drive may call it."""

    async def body() -> None:
        w = World(MemoryStore())
        rt = w.runtime()
        real, callers = rt.driver.step, []

        async def spy(run_id: RunId) -> Any:
            callers.append(sys._getframe(1).f_code.co_name)
            return await real(run_id)

        rt.driver.step = spy  # type: ignore[method-assign]
        async with w.up(rt) as api:
            run_id = await api.to_review_gate()
            await api.decide(run_id, "review_gate")
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
        assert callers
        assert set(callers) == {"_drive"}, callers

    run(body())


def test_key_names_do_not_leak_secrets_in_errors() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            r = await api.c.get("/runs", headers={"Authorization": "Bearer wrong-token"})
            assert r.status_code == 401
            assert "wrong-token" not in r.text
            assert TOKEN not in r.text

    run(body())


# --- review pass 1: vetoes, Stop option, failed drives, conflicts, services ---------------------


@pytest.mark.parametrize("kind", ["reject", "request_changes"])
@pytest.mark.parametrize("comment", ["", "   "])
def test_a_veto_without_a_comment_is_a_422_and_the_gate_stays_open(kind: str, comment: str) -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            run_id = await api.to_review_gate()
            r = await api.decide(run_id, "review_gate", kind, comment=comment)
            assert (r.status_code, code_of(r)) == (422, "comment_required")
            assert (await api.gate(run_id, "review_gate"))["status"] == "OPEN"
            ok = await api.decide(run_id, "review_gate", kind, comment="because")
            assert ok.status_code == 202  # the veto itself is never delayed

    run(body())


def test_the_spec_says_a_comment_is_required_and_documents_the_error_body() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            spec = (await api.c.get("/openapi.json")).json()
            comment = spec["components"]["schemas"]["DecisionIn"]["properties"]["comment"]
            assert "Required" in comment["description"]
            assert "approve" in comment["description"]
            decide = spec["paths"]["/runs/{run_id}/gates/{name}/{round}/decisions"]["post"]
            assert "comment" in decide["description"]
            assert "comment_required" in decide["responses"]["422"]["description"]
            fields = spec["components"]["schemas"]["ErrorBody"]["properties"]
            assert {"closed_by", "decision_recorded", "stop", "gate", "round"} <= set(fields)
            for path, op in [
                (p, o) for p, ms in spec["paths"].items() for o in ms.values() if p != "/healthz"
            ]:
                ref = op["responses"]["422"]["content"]["application/json"]["schema"]["$ref"]
                assert ref.endswith("/ErrorResponse"), path

    run(body())


class Faulty:
    """Store wrapper: once ``allow`` driver writes have passed, every write to a run's driver
    record raises a conflict (``None`` is off). Gate and effect writes are untouched."""

    def __init__(self, inner: Store) -> None:
        self.inner = inner
        self.allow: int | None = None
        self.burst: int | None = None  # None: fail for good; n: fail n writes, then recover
        self.exc: Callable[[], Exception] = lambda: TransactionConflictError("busy")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def transact(self, scope: Any, ops: Any) -> None:
        if self.allow is not None and any(
            getattr(o, "key", None) and o.key.sk == "DRIVER" for o in ops
        ):
            if self.allow > 0:
                self.allow -= 1
            elif self.burst is None:
                raise self.exc()
            elif self.burst > 0:
                self.burst -= 1
                raise self.exc()
        self.inner.transact(scope, ops)


def test_a_decision_whose_drive_dies_is_driven_again_when_it_is_repeated() -> None:
    async def body() -> None:
        store = Faulty(MemoryStore())
        w = World(store)
        async with w.up() as api:
            run_id = await api.to_review_gate()
            await api.quiet()
            store.allow = 1  # the submit lands; the drive that follows cannot write anything
            assert (await api.decide(run_id, "review_gate")).status_code == 202
            rid = RunId.parse(run_id)
            err = await until("the drive to give up", lambda: api.rt.driver_error(rid))
            assert "TransactionConflictError" in err
            assert api.rt.driver.pending_events(rid) == 1  # durable, and nobody is driving it
            assert (await api.run(run_id))["stage"] == "review_gate"
            store.allow = None  # the store recovers; the person repeats the decision
            again = await api.decide(run_id, "review_gate")
            assert again.status_code == 409  # it is closed
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            kinds = [e["type"] for e in api.rt.driver.timeline(rid)]
            assert kinds.count("gate.closed") == 1

    run(body())


def test_a_stop_whose_drive_dies_is_driven_again_when_it_is_repeated() -> None:
    async def body() -> None:
        store = Faulty(MemoryStore())
        w = World(store)
        async with w.up() as api:
            run_id = await api.to_review_gate()
            rid = RunId.parse(run_id)
            await api.quiet()
            store.allow = 3  # submit, claim and apply land; the Stop's own write cannot
            assert (await api.call("POST", f"/runs/{run_id}/cancel")).status_code == 202
            await until("the drive to give up", lambda: api.rt.driver_error(rid))
            assert (await api.run(run_id))["status"] == "CANCELLING"
            store.allow = None
            again = await api.call("POST", f"/runs/{run_id}/cancel")
            assert (again.status_code, code_of(again)) == (409, "run_finished")
            await api.wait_for(run_id, "CANCELLED")

    run(body())


@pytest.mark.parametrize(
    "exc", [lambda: TransactionConflictError("busy"), lambda: ConditionFailedError([0])]
)
def test_a_transient_drive_error_is_retried_with_backoff_inside_the_drive(
    exc: Callable[[], Exception],
) -> None:
    async def body() -> None:
        sleeps: list[float] = []

        async def nap(s: float) -> None:
            sleeps.append(s)

        store = Faulty(MemoryStore())
        store.exc = exc
        w = World(store)
        async with w.up(w.runtime(api_sleep=nap)) as api:
            run_id = await api.to_review_gate()
            rid = RunId.parse(run_id)
            await api.quiet()
            sleeps.clear()
            # the driver's own 8 retries are used up by one claim, twice over
            store.allow, store.burst = 1, 16
            assert (await api.decide(run_id, "review_gate")).status_code == 202
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            await until("the report to clear", lambda: api.rt.driver_error(rid) is None)
            assert len(sleeps) == 2, sleeps
            assert 0 < sleeps[0] < sleeps[1], "the retries must back off"

    run(body())


@pytest.mark.parametrize(
    "exc", [lambda: TransactionConflictError("busy"), lambda: ConditionFailedError([0])]
)
def test_store_conflicts_on_start_cancel_and_decide_are_503_not_500(
    exc: Callable[[], Exception],
) -> None:
    async def body() -> None:
        store = Faulty(MemoryStore())
        store.exc = exc
        w = World(store)
        async with w.up() as api:
            store.allow = 0
            if isinstance(exc(), TransactionConflictError):  # a lost race on start means "exists"
                made = await api.call("POST", "/runs", json={"ticket": "T"})
                assert (made.status_code, code_of(made)) == (503, "store_conflict")
                assert made.headers["retry-after"]
            store.allow = None
            run_id = await api.to_review_gate()
            store.allow = 0
            stop = await api.call("POST", f"/runs/{run_id}/cancel")
            assert (stop.status_code, code_of(stop)) == (503, "store_conflict")
            assert stop.headers["retry-after"]
            dec = await api.decide(run_id, "review_gate")
            assert (dec.status_code, code_of(dec)) == (503, "delivery_failed")
            assert dec.json()["error"]["decision_recorded"] is True
            store.allow = None

    run(body())


def test_a_write_that_is_durable_is_answered_even_if_the_follow_up_read_fails() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()

            async def broken(*a: Any, **k: Any) -> Any:
                raise TransactionConflictError("busy")

            api.rt.get_run = broken  # type: ignore[method-assign]
            assert (await api.call("POST", f"/runs/{run_id}/cancel")).status_code == 202
            made = await api.call("POST", "/runs", json={"ticket": "T"})
            assert made.status_code == 202
            assert made.json()["status"] == "QUEUED"

    run(body())


def test_gate_contention_is_a_503_with_its_own_code() -> None:
    from sto.gates.service import GateContentionError
    from sto.store.ports import ConditionFailedError

    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            for error in (GateContentionError("kept changing"), ConditionFailedError([0])):

                def boom(*a: Any, error: Exception = error, **k: Any) -> Any:
                    raise error

                w.gates.decide = boom  # type: ignore[method-assign]
                r = await api.decide(run_id, "review_gate")
                assert (r.status_code, code_of(r)) == (503, "gate_contention")
                assert r.headers["retry-after"]

    run(body())


def test_delivery_failed_is_reported_on_every_attempt_not_only_the_first() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()

            async def down(rid: RunId, event: object) -> None:
                raise OSError("disk went away")

            api.rt.driver.submit = down  # type: ignore[method-assign,assignment]
            for _ in range(2):
                r = await api.decide(run_id, "review_gate")
                assert (r.status_code, code_of(r)) == (503, "delivery_failed")

    run(body())


# --- redelivery: each guard has a test that fails without it ------------------------------------


def _close_directly(w: World, run_id: str, g: dict[str, Any], kind: DecisionKind) -> Any:
    return w.gates.decide(
        SCOPE,
        run_id=RunId.parse(run_id),
        gate=g["name"],
        round=g["round"],
        kind=kind,
        actor="dev",
        surface=Surface.UI,
        subject_digest=g["subject_digest"],
        comment="because",
    )


def test_an_event_already_queued_is_not_queued_again_and_is_driven() -> None:
    from sto.api.runtime import _closed_event

    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            rid = RunId.parse(run_id)
            decided = _close_directly(
                w, run_id, await api.gate(run_id, "review_gate"), DecisionKind.APPROVE
            )
            # queued by a submit whose drive never happened
            await api.rt.driver.submit(rid, _closed_event(decided.gate, decided.decision))
            assert await api.rt.redeliver(rid) is False  # it is there already...
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")  # ...and gets driven
            assert api.rt.driver.rejected(rid) == []
            kinds = [e["type"] for e in api.rt.driver.timeline(rid)]
            assert kinds.count("gate.closed") == 1

    run(body())


def test_a_run_that_is_not_waiting_is_not_sent_a_decision() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            rid = RunId.parse(run_id)
            assert (await api.call("POST", f"/runs/{run_id}/cancel")).status_code == 202
            await api.wait_for(run_id, "CANCELLED")
            # approving a stopped run's gate closes it but changes nothing else (D2-11)
            assert (await api.decide(run_id, "review_gate")).status_code == 202
            await until("the late event to be refused", lambda: api.rt.driver.rejected(rid))
            before = len(api.rt.driver.rejected(rid))
            assert await api.rt.redeliver(rid) is False
            await asyncio.sleep(0.05)
            assert len(api.rt.driver.rejected(rid)) == before
            assert (await api.run(run_id))["status"] == "CANCELLED"

    run(body())


def test_a_decision_and_a_redelivery_racing_queue_the_event_once() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            rid = RunId.parse(run_id)
            real = api.rt.driver.submit

            async def slow(r: RunId, event: object) -> None:
                await asyncio.sleep(0.2)
                await real(r, event)

            api.rt.driver.submit = slow  # type: ignore[method-assign,assignment]
            deciding = asyncio.ensure_future(api.decide(run_id, "review_gate"))

            def closed() -> bool:
                item = w.store.get(SCOPE, Key(f"RUN#{run_id}", "GATE#review_gate#1"))
                return item is not None and item.data["status"] == "APPROVED"

            await until("the gate to close", closed)
            await api.rt.redeliver(rid)  # while the decision's own submit is still on its way
            assert (await deciding).status_code == 202
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            assert api.rt.driver.rejected(rid) == []
            kinds = [e["type"] for e in api.rt.driver.timeline(rid)]
            assert kinds.count("gate.closed") == 1

    run(body())


def test_a_recorded_veto_is_delivered_on_restart() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            _close_directly(w, run_id, await api.gate(run_id, "review_gate"), DecisionKind.REJECT)
        async with w.up(w.runtime(owner="second")) as api2:
            await api2.wait_for(run_id, "REJECTED")
            assert w.scm.merges() == []

    run(body())


# --- background services and start-up -----------------------------------------------------------


def test_a_dead_service_is_logged_and_shown_by_health(caplog: pytest.LogCaptureFixture) -> None:
    async def body() -> None:
        w = World(MemoryStore())

        async def merge_queue() -> None:
            raise RuntimeError("queue exploded")

        async def fine() -> None:
            await asyncio.sleep(3600)

        rt = w.runtime()
        app = create_app(rt, token=TOKEN, mode="local", services=[merge_queue, fine])
        with caplog.at_level(logging.ERROR, logger="sto.api"):
            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
                async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                    got = await until(
                        "health to report the service",
                        lambda: _health(c),
                    )
                    assert got["ok"] is False
                    assert got["failed_services"] == ["merge_queue"]
                    assert any("queue exploded" in r.getMessage() for r in caplog.records)

    async def _health(c: httpx.AsyncClient) -> dict[str, Any] | None:
        r = await c.get("/healthz")  # no token needed
        return dict(r.json()) if r.status_code == 503 else None

    run(body())


def test_health_is_ok_when_everything_is_alive() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            r = await api.c.get("/healthz")
            assert (r.status_code, r.json()["ok"]) == (200, True)

    run(body())


def test_the_demo_merge_queue_survives_a_merge_that_a_stop_dequeued() -> None:
    from sto.api.app import land_pending

    w = World(MemoryStore())
    pr = w.default_pr
    gone = w.scm.request_merge(pr, "abc", MergeMethod.SQUASH, "k1")
    w.scm.dequeue(pr, "abc")
    landed = land_pending(w.scm, 0)  # must not raise
    assert landed == len(w.scm.merges()) == 1
    assert gone in w.scm.merges()


def test_one_run_that_cannot_be_redelivered_does_not_stop_the_api(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            bad = await api.to_review_gate()
            good = await api.to_review_gate()
            _close_directly(w, good, await api.gate(good, "review_gate"), DecisionKind.APPROVE)
        rt = w.runtime(owner="second")
        real = rt.redeliver

        async def picky(run_id: RunId) -> bool:
            if str(run_id) == bad:
                raise OSError("unreadable")
            return await real(run_id)

        rt.redeliver = picky  # type: ignore[method-assign]
        with caplog.at_level(logging.ERROR, logger="sto.api"):
            try:
                await rt.start()
            except Exception as e:
                raise AssertionError(f"one bad run stopped start-up: {e!r}") from e
            async with w.up(rt) as api2:
                await api2.wait_for(good, "WAITING_HUMAN", "qa_gate")
                assert any("unreadable" in r.getMessage() for r in caplog.records)
                # and the bad run says so itself, not only the log
                await until(
                    "the error on the run",
                    lambda: "unreadable" in (api2.rt.driver_error(RunId.parse(bad)) or ""),
                )

    run(body())


def test_closing_the_runtime_releases_the_leases(tmp_path: Path) -> None:
    async def body() -> None:
        w = World(SqliteStore(tmp_path / "s.db"))
        w.steps.hold["implement"] = asyncio.Event()  # a drive is in the middle of a step
        async with w.up() as api:
            run_id = await api.new_run()
            await until("the step to start", lambda: w.steps.calls)
            item = w.store.get(SCOPE, Key(f"RUN#{run_id}", "DRIVER"))
            assert item is not None
            assert item.data["lease"] is not None  # held while it works
        item = w.store.get(SCOPE, Key(f"RUN#{run_id}", "DRIVER"))
        assert item is not None
        assert item.data["lease"] is None, "a graceful shutdown must give the run up"

    run(body())


# --- review pass 2 ------------------------------------------------------------------------------


async def _qa_pending_with_dead_drive(w: World, store: Faulty, api: Api) -> str:
    """Approve the review gate so the decision is applied (the run is RUNNING at qa with its
    step queued), and make the drive die before the step runs."""
    run_id = await api.to_review_gate()
    await api.quiet()
    store.allow = 3  # submit, claim and apply land; nothing after them can write
    assert (await api.decide(run_id, "review_gate")).status_code == 202
    await until("the drive to give up", lambda: api.rt.driver_error(RunId.parse(run_id)))
    got = await api.run(run_id)
    assert (got["status"], got["stage"]) == ("RUNNING", "qa")
    return run_id


def test_a_repeated_decision_drives_a_run_that_is_already_past_the_gate() -> None:
    async def body() -> None:
        store = Faulty(MemoryStore())
        w = World(store)
        async with w.up() as api:
            run_id = await _qa_pending_with_dead_drive(w, store, api)
            before = len(w.steps.calls)
            store.allow = None  # the store recovers; the person presses Approve again
            again = await api.decide(run_id, "review_gate")
            assert (again.status_code, code_of(again)) == (409, "gate_closed")
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            assert len(w.steps.calls) > before

    run(body())


def test_a_repeated_decision_drives_a_run_whose_step_was_broken_and_is_fixed() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            w.steps.boom = RuntimeError("qa step broke")
            assert (await api.decide(run_id, "review_gate")).status_code == 202
            rid = RunId.parse(run_id)
            await until(
                "the step fault", lambda: "qa step broke" in (api.rt.driver_error(rid) or "")
            )
            before = len(w.steps.calls)
            w.steps.boom = None
            again = await api.decide(run_id, "review_gate")
            assert (again.status_code, code_of(again)) == (409, "gate_closed")
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            assert len(w.steps.calls) > before

    run(body())


def test_a_run_left_with_queued_work_is_finished_after_a_restart() -> None:
    async def body() -> None:
        store = Faulty(MemoryStore())
        w = World(store)
        async with w.up() as api:
            run_id = await _qa_pending_with_dead_drive(w, store, api)
            store.allow = None
        async with w.up(w.runtime(owner="second")) as api2:
            await api2.wait_for(run_id, "WAITING_HUMAN", "qa_gate")

    run(body())


def test_a_repeated_stop_drives_a_run_that_has_nothing_else_to_say() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.new_run()
            await api.wait_for(run_id, "WAITING_HUMAN", "review_gate")
            rid = RunId.parse(run_id)
            real = api.rt.driver.run_until_idle
            calls: list[int] = []

            async def counting(r: RunId) -> Any:
                calls.append(1)
                return await real(r)

            api.rt.driver.run_until_idle = counting  # type: ignore[method-assign,assignment]
            await api.quiet()
            await api.call("POST", f"/runs/{run_id}/cancel")
            await api.wait_for(run_id, "CANCELLED")
            calls.clear()
            again = await api.call("POST", f"/runs/{run_id}/cancel")
            assert (again.status_code, code_of(again)) == (409, "run_finished")
            await until("the repeat to drive the run", lambda: calls)
            assert rid

    run(body())


def test_a_resume_failure_is_reported_while_another_run_is_still_polling() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        w.steps.queue = ["hold", "hold"]
        async with w.up() as api:
            a = await api.new_run("A")
            b = await api.new_run("B")
            await until("both steps to start", lambda: len(w.steps.calls) == 2)
        w.steps.modes.clear()
        w.steps.queue = ["fail", "poll"]  # the same two runs, in the same order, after a restart
        w.steps.modes.update({})
        async with w.up(w.runtime(owner="second")) as api2:
            ra, rb = RunId.parse(a), RunId.parse(b)
            w.steps.modes[ra], w.steps.modes[rb] = "fail", "poll"
            await until("A's failure", lambda: api2.rt.driver_error(ra))
            polling = [t.get_name() for t in api2.rt.background_tasks()]
            assert f"drive:{rb}" in polling, "B must still be polling when A's failure shows"
            assert api2.rt.driver_error(rb) is None

    run(body())


def test_an_error_on_one_run_is_not_erased_when_another_run_finishes() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            a, b = await api.new_run("A"), await api.new_run("B")
            ra, rb = RunId.parse(a), RunId.parse(b)
            await api.wait_for(a, "WAITING_HUMAN", "review_gate")
            await api.wait_for(b, "WAITING_HUMAN", "review_gate")
            w.steps.modes[ra] = "fail"
            w.steps.modes[rb] = "hold"
            assert (await api.decide(a, "review_gate")).status_code == 202
            await until("A's error", lambda: api.rt.driver_error(ra))
            assert (await api.decide(b, "review_gate")).status_code == 202
            await until("B to be in its held step", lambda: f"drive:{rb}" in _names(api))
            w.steps.released.set()
            await api.wait_for(b, "WAITING_HUMAN", "qa_gate")
            await api.quiet()
            assert api.rt.driver_error(ra), "B finishing must not clear A's error"
            assert api.rt.driver_error(rb) is None

    def _names(api: Api) -> list[str]:
        return [t.get_name() for t in api.rt.background_tasks()]

    run(body())


def test_a_transient_error_while_resuming_is_retried() -> None:
    async def body() -> None:
        store = Faulty(MemoryStore())
        w = World(store)
        w.steps.queue = ["hold"]
        async with w.up() as api:
            run_id = await api.new_run()
            await until("the step to start", lambda: w.steps.calls)
        w.steps.modes.clear()
        store.allow, store.burst = 0, 8  # the first claim after the restart loses all 8 tries
        async with w.up(w.runtime(owner="second")) as api2:
            await api2.wait_for(run_id, "WAITING_HUMAN", "review_gate")
            assert api2.rt.driver_error(RunId.parse(run_id)) is None

    run(body())


def test_a_run_leased_by_a_dead_driver_is_waited_for_on_restart() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        w.steps.queue = ["hold"]
        async with w.up() as api:
            run_id = await api.new_run()
            await until("the step to start", lambda: w.steps.calls)
            for t in list(api.rt._tasks.values()):  # the process dies: no release
                t.cancel()
            await asyncio.gather(*api.rt._tasks.values(), return_exceptions=True)
            w.steps.modes.clear()
            async with w.up(w.runtime(owner="second")) as api2:
                await api2.wait_for(run_id, "WAITING_HUMAN", "review_gate")

    run(body())


def test_a_failed_startup_redelivery_stays_on_the_run_and_is_retried() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            _close_directly(w, run_id, await api.gate(run_id, "review_gate"), DecisionKind.APPROVE)
        rt = w.runtime(owner="second")
        real = rt.redeliver
        broken = True

        async def flaky(r: RunId) -> bool:
            if broken:
                raise OSError("unreadable")
            return await real(r)

        rt.redeliver = flaky  # type: ignore[method-assign,assignment]
        async with w.up(rt) as api2:
            rid = RunId.parse(run_id)
            await until(
                "the error on the run", lambda: "unreadable" in (rt.driver_error(rid) or "")
            )
            # the resume drive of this run is long over, yet the error stays: the decision is not in
            await until(
                "the drives to end",
                lambda: not [t for t in rt.background_tasks() if t.get_name().startswith("drive:")],
            )
            got = await api2.run(run_id)
            assert "unreadable" in got["driver_error"]
            assert (got["status"], got["stage"]) == ("WAITING_HUMAN", "review_gate")
            health = (await api2.c.get("/healthz")).json()
            assert (health["ok"], health["degraded"]) == (True, True)
            broken = False  # retried without anyone repeating the decision
            await api2.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            await until("the error to clear", lambda: rt.driver_error(rid) is None)

    run(body())


def test_a_blank_subject_digest_is_a_422_and_so_is_every_other_refused_field() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            run_id = await api.to_review_gate()
            base = f"/runs/{run_id}/gates"
            g = await api.gate(run_id, "review_gate")
            for body_ in (
                {"kind": "approve", "subject_digest": "   "},
                {"kind": "approve", "subject_digest": "\t"},
            ):
                r = await api.call("POST", f"{base}/review_gate/1/decisions", json=body_)
                assert (r.status_code, code_of(r)) == (422, "subject_digest_required")
            waive = {"kind": "waive", "subject_digest": g["subject_digest"], "comment": "x"}
            r = await api.call("POST", f"{base}/review_gate/1/decisions", json=waive)
            assert (r.status_code, code_of(r)) == (422, "decision_not_allowed")
            long_name = "g" * 300
            r = await api.call("POST", f"{base}/{long_name}/1/decisions", json=waive)
            assert r.status_code == 422, r.text
            r = await api.call("POST", f"{base}/review_gate/0/decisions", json=waive)
            assert r.status_code == 422, r.text
            veto = {"kind": "reject", "subject_digest": "", "comment": "no"}
            r = await api.call("POST", f"{base}/review_gate/1/decisions", json=veto)
            assert r.status_code == 202, r.text  # a veto needs no digest

            def boom(*a: Any, **k: Any) -> Any:
                raise ValueError("a field this route did not foresee")

            w.gates.decide = boom  # type: ignore[method-assign]
            r = await api.call("POST", f"{base}/qa_gate/1/decisions", json={**veto, "comment": "x"})
            assert (r.status_code, code_of(r)) == (422, "invalid_decision")

    run(body())


def test_a_run_read_under_a_store_conflict_is_503() -> None:
    class ReadFlaky:
        def __init__(self, inner: Store) -> None:
            self.inner, self.on = inner, False

        def __getattr__(self, name: str) -> Any:
            return getattr(self.inner, name)

        def get(self, scope: Any, key: Key) -> Any:
            if self.on and key.pk == "RUNS_API":
                raise TransactionConflictError("busy")
            return self.inner.get(scope, key)

    async def body() -> None:
        store = ReadFlaky(MemoryStore())
        w = World(store)
        async with w.up() as api:
            run_id = await api.new_run()
            store.on = True
            r = await api.call("GET", f"/runs/{run_id}")
            assert (r.status_code, code_of(r)) == (503, "store_conflict")
            assert r.headers["retry-after"]
            store.on = False

    run(body())


def test_health_says_degraded_when_a_run_carries_an_error() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        async with w.up() as api:
            ok = (await api.c.get("/healthz")).json()
            assert (ok["ok"], ok["degraded"], ok["runs_with_errors"]) == (True, False, 0)
            w.steps.boom = RuntimeError("broken")
            run_id = await api.new_run()
            await until("the error", lambda: api.rt.driver_error(RunId.parse(run_id)))
            r = await api.c.get("/healthz")
            assert r.status_code == 200  # liveness is unchanged
            assert (r.json()["ok"], r.json()["degraded"], r.json()["runs_with_errors"]) == (
                True,
                True,
                1,
            )
            spec = (await api.c.get("/openapi.json")).json()
            assert "degraded" in spec["components"]["schemas"]["Health"]["properties"]

    run(body())


def test_stop_is_offered_only_while_there_is_something_to_stop() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            run_id = await api.to_review_gate()
            first = await api.decide(run_id, "review_gate", "reject", comment="no")
            assert first.status_code == 202
            await api.wait_for(run_id, "REJECTED")
            again = await api.decide(run_id, "review_gate", "reject", comment="no")
            assert (again.status_code, code_of(again)) == (409, "gate_closed")
            assert "stop" not in again.json()["error"]
            live = await api.to_review_gate()
            await api.decide(live, "review_gate")
            await api.wait_for(live, "WAITING_HUMAN", "qa_gate")
            closed = await api.decide(live, "review_gate")
            assert closed.json()["error"]["stop"]["href"] == f"/runs/{live}/cancel"

    run(body())


def test_closing_survives_a_store_that_cannot_list_the_runs() -> None:
    async def body() -> None:
        w = World(MemoryStore())
        rt = w.runtime()
        await rt.start()

        async def down() -> Any:
            raise TransactionConflictError("busy")

        rt.driver.active_runs = down  # type: ignore[method-assign]
        await rt.close()  # must not raise

    run(body())


def test_the_local_state_directory_ignores_itself(tmp_path: Path) -> None:
    env = {"STO_MODE": "local", "STO_DB": str(tmp_path / ".sto" / "dev.db")}
    build_local(env)
    assert (tmp_path / ".sto" / ".gitignore").read_text() == "*\n"
    (tmp_path / ".sto" / ".gitignore").write_text("*\n!keep\n")
    build_local(env)  # an existing file is left alone
    assert (tmp_path / ".sto" / ".gitignore").read_text() == "*\n!keep\n"


def test_no_store_call_runs_on_the_event_loop_while_a_run_is_driven() -> None:
    import threading

    class Spy:
        def __init__(self, inner: Store) -> None:
            self.inner = inner
            self.threads: list[int] = []

        def __getattr__(self, name: str) -> Any:
            attr = getattr(self.inner, name)
            if name in ("get", "query", "transact", "put", "delete"):

                def spied(*a: Any, **k: Any) -> Any:
                    self.threads.append(threading.get_ident())
                    return attr(*a, **k)

                return spied
            return attr

    async def body() -> None:
        spy = Spy(MemoryStore())
        w = World(spy)
        loop_thread = threading.get_ident()
        async with w.up() as api:
            lander = asyncio.ensure_future(w.land_merges())
            try:
                run_id = await api.to_review_gate()
                await api.decide(run_id, "review_gate")
                await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
                await api.decide(run_id, "qa_gate")
                await api.wait_for(run_id, "DONE")
                await api.call("GET", "/runs")
                await api.call("GET", f"/runs/{run_id}/events")
            finally:
                lander.cancel()
        assert spy.threads
        assert loop_thread not in spy.threads, "a store call ran on the event loop"

    run(body())


if os.environ.get("STO_TEST_DEBUG"):  # pragma: no cover
    logging.basicConfig(level=logging.DEBUG)
