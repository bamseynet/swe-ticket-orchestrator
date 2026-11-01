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
from sto.store.ports import Key, Store, TeamScope, TransactionConflictError
from sto.store.sqlite import SqliteStore

SCOPE = TeamScope("t1")
TOKEN = "dev-token"
REPO = RepoRef("acme", "app")
AUTH = {"Authorization": f"Bearer {TOKEN}"}


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
        self.trace: list[tuple[str, str]] = []

    async def execute(self, key: str, command: object) -> Outcome:
        if not isinstance(command, RunStep):
            raise AssertionError(f"unexpected command {command!r}")
        self.calls.append(command.stage)
        self.trace.append((str(command.run_id)[-4:], command.stage))
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
            transport = httpx.ASGITransport(app=app)
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
        self, run_id: str, name: str, kind: str = "approve", *, digest: str | None = None
    ) -> httpx.Response:
        g = await self.gate(run_id, name)
        body = {"kind": kind, "subject_digest": digest or g["subject_digest"], "comment": "ok"}
        return await self.call(
            "POST", f"/runs/{run_id}/gates/{name}/{g['round']}/decisions", json=body
        )

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

    run(body())


def test_decision_refusals_have_their_own_status() -> None:
    async def body() -> None:
        async with World(MemoryStore()).up() as api:
            run_id = await api.to_review_gate()
            g = await api.gate(run_id, "review_gate")
            base = f"/runs/{run_id}/gates"
            ok = {"kind": "approve", "subject_digest": g["subject_digest"]}
            missing = await api.call("POST", f"{base}/nope/1/decisions", json=ok)
            assert (missing.status_code, missing.json()["error"]["code"]) == (404, "gate_not_found")
            stale = await api.decide(run_id, "review_gate", digest="0" * 64)
            assert (stale.status_code, stale.json()["error"]["code"]) == (409, "stale_subject")
            bad = await api.call(
                "POST", f"{base}/review_gate/1/decisions", json={**ok, "kind": "x"}
            )
            assert bad.status_code == 422
            retest = await api.decide(run_id, "review_gate", "retest")
            assert (retest.status_code, retest.json()["error"]["code"]) == (
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
            assert first.json()["error"]["code"] == "delivery_failed"
            assert first.json()["error"]["decision_recorded"] is True
            assert (await api.gate(run_id, "review_gate"))["status"] == "APPROVED"
            assert (await api.run(run_id))["stage"] == "review_gate"
            again = await api.decide(run_id, "review_gate")  # the retry: closed, and it heals
            assert again.status_code == 409
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            kinds = [e["type"] for e in api.rt.driver.timeline(RunId.parse(run_id))]
            assert kinds.count("gate.closed") == 1, "the decision must be delivered exactly once"

    run(body())


def test_redelivery_does_not_duplicate_a_decision_that_is_already_queued(tmp_path: Path) -> None:
    async def body() -> None:
        w = World(SqliteStore(tmp_path / "s.db"))
        async with w.up() as api:
            run_id = await api.to_review_gate()
            assert (await api.decide(run_id, "review_gate")).status_code == 202
            await api.wait_for(run_id, "WAITING_HUMAN", "qa_gate")
            await api.rt.redeliver(RunId.parse(run_id))
            await api.rt.redeliver(RunId.parse(run_id))
            assert api.rt.driver.rejected(RunId.parse(run_id)) == []

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
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c,
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
            transport = httpx.ASGITransport(app=app)
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
                assert r.json()["error"]["code"] == "store_conflict"
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


if os.environ.get("STO_TEST_DEBUG"):  # pragma: no cover
    logging.basicConfig(level=logging.DEBUG)
