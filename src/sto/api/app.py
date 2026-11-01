"""The API application (D1-08): FastAPI over the runtime, behind a dev token.

* **Dev auth only runs in local mode.** ``create_app`` raises ``DevAuthRefusedError`` unless
  ``mode`` is exactly ``"local"``, and ``build_local`` / ``main`` read it from ``STO_MODE``, which
  must be set to ``local`` (unset is refused: fail closed). Real sign-in is D3.
* ``build_local`` is the stack ``make dev`` serves: the SQLite store (so a waiting gate survives
  a restart), the fake SCM, simulated steps, and a simulated merge queue. ``Runtime.start``
  brings unfinished runs back with ``resume_all`` when the app starts.
* No request holds work open: handlers record and return, the runtime drives in the background.

Run it: ``STO_MODE=local python -m sto.api.app`` (``make dev``). Environment: ``STO_DB`` (file,
default ``.sto/dev.db``), ``STO_DEV_TOKEN`` (default ``dev-token``, loopback only),
``STO_API_PORT`` (default 8710), ``STO_POLL_INTERVAL`` (seconds, default 1).
"""

import asyncio
import contextlib
import dataclasses
import hmac
import logging
import os
import sys
from collections.abc import AsyncIterator, Callable, Coroutine, Mapping, Sequence
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import MergeMethod, PrRef, PrSpec, RepoRef
from sto.api.routers import gates, runs
from sto.api.routers.runs import ApiError
from sto.api.runtime import Runtime, scm_merge_factory
from sto.domain import RunId, StepKey, Subject
from sto.effects.core import EffectExecutor
from sto.engine.commands import RunEffect, RunStep
from sto.engine.drivers.ports import Done, Outcome
from sto.engine.handlers.core import StepSucceeded
from sto.gates.service import GateService
from sto.store.ports import TeamScope
from sto.store.sqlite import SqliteStore

log = logging.getLogger("sto.api")

DEFAULT_TOKEN = "dev-token"  # noqa: S105 - the documented local default, loopback only
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
Service = Callable[[], Coroutine[None, None, None]]


class DevAuthRefusedError(RuntimeError):
    """The dev token only works in local mode."""


def create_app(
    runtime: Runtime,
    *,
    token: str,
    mode: str,
    services: Sequence[Service] = (),
) -> FastAPI:
    """The app. ``services`` are background coroutines that run while it is up (the local
    stack's simulated merge queue)."""
    if mode != "local":
        raise DevAuthRefusedError(
            f"dev auth only runs in local mode (STO_MODE=local); this is {mode!r}"
        )
    if not token:
        raise DevAuthRefusedError("the dev token must not be empty")

    bearer = HTTPBearer(auto_error=False, description="The dev token (local mode only).")

    def authorize(
        creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> None:
        # Compared in constant time; the token is never echoed.
        if creds is None or not hmac.compare_digest(creds.credentials.encode(), token.encode()):
            raise ApiError(
                401,
                "unauthorized",
                "a valid dev token is required",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await runtime.start()
        tasks: list[asyncio.Task[None]] = [
            asyncio.get_running_loop().create_task(s(), name="service") for s in services
        ]
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await runtime.close()

    app = FastAPI(
        title="SWE Ticket Orchestrator API",
        version="0.0.0",
        summary="Runs, events by cursor, gates and decisions (v0, dev token).",
        lifespan=lifespan,
    )
    app.state.runtime = runtime

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        body = {"code": exc.code, "message": exc.message, **exc.extra}
        return JSONResponse({"error": body}, status_code=exc.http_status, headers=exc.headers)

    protected = [Depends(authorize)]
    app.include_router(runs.router, dependencies=protected)
    app.include_router(gates.router, dependencies=protected)
    return app


# --- the local stack ----------------------------------------------------------------------------

DEMO_REPO = RepoRef("acme", "demo")


class SimulatedSteps:
    """Steps of the local stack: each succeeds at once with the subject of the demo PR's head.
    The real agents arrive with D1-05 and the demo with D1-10; nothing here is analysis."""

    def __init__(self, subject_for: Callable[[RunId], Subject]) -> None:
        self._subject_for = subject_for

    async def execute(self, key: str, command: object) -> Outcome:
        if not isinstance(command, RunStep):
            raise TypeError(f"unexpected command {type(command).__name__}")
        subject = self._subject_for(command.run_id)
        key_ = StepKey(command.run_id, command.stage, command.visit, command.attempt)
        return Done([StepSucceeded(key_, subject)])


def build_local(env: Mapping[str, str] | None = None) -> FastAPI:
    """The app ``make dev`` serves. Refuses outside local mode before it opens anything."""
    env = os.environ if env is None else env
    mode = env.get("STO_MODE", "")
    if mode != "local":
        raise DevAuthRefusedError(
            f"dev auth only runs in local mode (STO_MODE=local); STO_MODE is {mode!r}"
        )
    path = Path(env.get("STO_DB", ".sto/dev.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    scope = TeamScope("local")
    store = SqliteStore(path)  # a waiting gate survives a restart
    scm = FakeScm()
    scm.seed_branch(DEMO_REPO, "main", "b0")
    scm.seed_branch(DEMO_REPO, "sto/demo", "abc", parent="b0")
    pr = PrRef.of(
        DEMO_REPO,
        scm.ensure_draft_pr(
            PrSpec(DEMO_REPO, "sto/demo", "main", "Demo", "A simulated PR"), "demo"
        ),
    )
    scm.mark_ready(pr, "demo-ready")

    def subject_for(run_id: RunId) -> Subject:
        return Subject(
            patch_id="p1",
            ticket_revision="r1",
            head_sha=scm.pr_head(pr),
            evidence_digest="e1",
            attention_digest="a1",
        )

    def live(cmd: RunEffect) -> Subject:
        # Read now, from the SCM (the head). The ticket revision is the demo's constant.
        return dataclasses.replace(cmd.subject, head_sha=scm.pr_head(pr), ticket_revision="r1")

    runtime = Runtime(
        store,
        scope,
        gates=GateService(store),
        effects=EffectExecutor(store, scope),
        steps=SimulatedSteps(subject_for),
        merges=scm_merge_factory(scm, store, scope, lambda run_id: pr, MergeMethod.SQUASH),
        live=live,
        poll_interval=float(env.get("STO_POLL_INTERVAL", "1")),
        lease_seconds=10.0,  # a restart after a kill waits at most this long for the old lease
    )

    async def merge_queue() -> None:
        """The simulated merge queue: lands whatever was requested."""
        landed = 0
        while True:
            merges = scm.merges()
            for handle in merges[landed:]:
                scm.complete_merge(handle, f"simulated-{landed}")
                landed += 1
            await asyncio.sleep(0.05)

    app = create_app(
        runtime, token=env.get("STO_DEV_TOKEN", DEFAULT_TOKEN), mode=mode, services=[merge_queue]
    )
    return app


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="Run the local API (dev token, SQLite store).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("STO_API_PORT", "8710")))
    args = parser.parse_args(argv)
    try:
        if (
            args.host not in LOOPBACK
            and os.environ.get("STO_DEV_TOKEN", DEFAULT_TOKEN) == DEFAULT_TOKEN
        ):
            raise DevAuthRefusedError(
                "refusing to bind beyond loopback with the default dev token; set STO_DEV_TOKEN"
            )
        app = build_local()
    except DevAuthRefusedError as e:
        print(f"sto.api: {e}", file=sys.stderr)
        return 2
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
