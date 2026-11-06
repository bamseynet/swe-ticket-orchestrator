"""The API application (D1-08): FastAPI over the runtime, behind a dev token.

* **Dev auth only runs in local mode.** ``create_app`` raises ``DevAuthRefusedError`` unless
  ``mode`` is exactly ``"local"``, and ``build_local`` / ``main`` read it from ``STO_MODE``, which
  must be set to ``local`` (unset is refused: fail closed). Real sign-in is D3.
* ``build_local`` is the stack ``make dev`` serves: the SQLite store (so a waiting gate survives
  a restart), the fake SCM, simulated steps, and a simulated merge queue. ``Runtime.start``
  kicks every unfinished run back into motion when the app starts.
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
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import MergeMethod, PrRef, PrSpec, RefusedError, RepoRef
from sto.api.auth import DOCS, Authorization, install_authorization
from sto.api.routers import attribution, gates, runs
from sto.api.routers import links as links_router
from sto.api.routers.attribution import read_records
from sto.api.routers.gates import DEV_ACTOR
from sto.api.routers.runs import ApiError, ErrorResponse
from sto.api.runtime import API_INDEX, Runtime, default_gate_roles, scm_merge_factory
from sto.config.schema import Floors
from sto.domain import RunId, StepKey, Subject
from sto.effects.core import EffectExecutor
from sto.engine.commands import RunEffect, RunStep
from sto.engine.drivers.ports import Done, Outcome
from sto.engine.handlers.core import StepSucceeded
from sto.engine.reducer import LINEAR_V0
from sto.gates.hooks import GateHooks
from sto.gates.moving import refuse_closed_ticket, refuse_moved_subject
from sto.gates.policy import GatePolicy, LinearGates, StoreRecords, build_gate_service
from sto.gates.service import DecisionPolicy, GateService
from sto.identity.linking import AccountLinking
from sto.identity.mapping import ServiceIdentity, UserIdentity
from sto.store.ports import Key, Scope, Store, TeamScope
from sto.store.sqlite import SqliteStore

log = logging.getLogger("sto.api")

DEFAULT_TOKEN = "dev-token"  # noqa: S105 - the documented local default, loopback only
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
Service = Callable[[], Coroutine[None, None, None]]


class Health(BaseModel):
    ok: bool = Field(description="Liveness: false only when a background service has died.")
    degraded: bool = Field(
        description="True when a run carries an error (a drive or a redelivery that failed) or "
        "start-up could not list the runs: the API is up but something needs a person."
    )
    failed_services: list[str]
    runs_with_errors: int


async def _supervised(name: str, service: Service, failed: dict[str, str]) -> None:
    """Run a background service; if it dies, say so in the log and in ``/healthz``."""
    try:
        await service()
    except asyncio.CancelledError:
        raise
    except Exception as e:
        failed[name] = f"{type(e).__name__}: {e}"
        log.exception("background service %s died: %r", name, e)


class DevAuthRefusedError(RuntimeError):
    """The dev token only works in local mode."""


def create_app(
    runtime: Runtime,
    *,
    token: str,
    mode: str,
    services: Sequence[Service] = (),
    authorization: Authorization | None = None,
    links: AccountLinking | None = None,
    session_of: Callable[[Request], str | None] | None = None,
) -> FastAPI:
    """The app. ``services`` are background coroutines that run while it is up (the local
    stack's simulated merge queue). With ``authorization`` (D3-03) every request is authorised by
    the middleware in ``sto.api.auth`` instead of the dev token, which is then neither checked
    nor built, and the mode is not restricted to local. The interactive docs are served (and
    public) only in local mode.

    ``links`` (D3-04) mounts the account-linking routes, only when given: v0 has no vendors.
    ``session_of`` must come with it and says which SSO session a request belongs to. It is never
    defaulted, and must not read a header the client can set: D3-27 (#396) adds a session field to
    ``Authorized`` for it to read, and until then the caller supplies it."""
    if (links is None) != (session_of is None):
        raise ValueError("links and session_of go together: pass both or neither")
    if authorization is None:
        if mode != "local":
            raise DevAuthRefusedError(
                f"dev auth only runs in local mode (STO_MODE=local); this is {mode!r}"
            )
        if not token:
            raise DevAuthRefusedError("the dev token must not be empty")

    protected: list[Any] = []
    if authorization is None:  # the dev token: not even built when the middleware is in charge
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

        protected = [Depends(authorize)]
    docs = authorization is None or mode == "local"  # the interactive docs: local mode only
    if authorization is not None and docs:
        authorization = dataclasses.replace(authorization, public=authorization.public | DOCS)

    failed: dict[str, str] = {}

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await runtime.start()
        tasks: list[asyncio.Task[None]] = [
            asyncio.get_running_loop().create_task(
                _supervised(getattr(s, "__name__", "service"), s, failed), name="service"
            )
            for s in services
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
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.runtime = runtime
    app.state.failed_services = failed

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        body = {"code": exc.code, "message": exc.message, **exc.extra}
        return JSONResponse({"error": body}, status_code=exc.http_status, headers=exc.headers)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Nothing about the fault goes to the client; it is logged here.
        log.error(
            "unhandled error on %s %s: %r", request.method, request.url.path, exc, exc_info=exc
        )
        body = {"code": "internal_error", "message": "the server could not process this request"}
        return JSONResponse({"error": body}, status_code=500)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [{"loc": [str(x) for x in e["loc"]], "msg": str(e["msg"])} for e in exc.errors()]
        body = {"code": "validation_error", "message": "the request is not valid", "fields": fields}
        return JSONResponse({"error": body}, status_code=422)

    @app.get("/healthz", tags=["health"], summary="Is the API healthy?", response_model=Health)
    async def health(response: Response) -> dict[str, Any]:
        """No token needed; says only whether the background parts are alive."""
        broken = sorted(failed)
        if broken:
            response.status_code = 503
        return {
            "ok": not broken,
            "degraded": runtime.degraded(),
            "failed_services": broken,
            "runs_with_errors": runtime.errors(),
        }

    shared: dict[int | str, dict[str, Any]] = {
        401: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    }
    app.include_router(runs.router, dependencies=protected, responses=shared)
    app.include_router(gates.router, dependencies=protected, responses=shared)
    app.include_router(attribution.router, dependencies=protected, responses=shared)
    if links is not None and session_of is not None:
        app.include_router(
            links_router.make_router(links, session_of=session_of),
            dependencies=protected,
            responses=shared,
        )
    if authorization is not None:
        install_authorization(app, authorization)
    return app


# --- the local stack ----------------------------------------------------------------------------

DEFAULT_DB = ".sto/dev.db"
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


def keep_out_of_git(directory: Path) -> None:
    """The default ``.sto`` directory, when this code created it, ignores itself (``*``), so the
    dev database is never committed and no one edits the repository's ``.gitignore``. A
    directory the user chose (``STO_DB``) or already had is never written to."""
    marker = directory / ".gitignore"
    try:
        if not marker.exists():
            marker.write_text("*\n")
    except OSError as e:  # a read-only directory must not stop the server from starting
        log.warning("could not write %s: %r", marker, e)


def land_pending(scm: FakeScm, landed: int) -> int:
    """Land the merges requested since the last call; a merge a Stop already dequeued is
    skipped, not an error. Returns how many have been handled."""
    merges = scm.merges()
    for handle in merges[landed:]:
        try:
            scm.complete_merge(handle, f"simulated-{landed}")
        except RefusedError as e:
            log.info("merge %s was not landed: %s", handle.id, e)
        landed += 1
    return landed


class DevDirectory:
    """The local stack's one person: the dev token's actor holds the roles of the linear v0 gates
    and is linked. Anyone else is unknown, so every other actor is refused."""

    ISSUER = "local"

    def __init__(self, team: str) -> None:
        self._me = UserIdentity(
            subject=DEV_ACTOR,
            issuer=self.ISSUER,
            memberships=frozenset({(team, "reviewer"), (team, "qa")}),
        )

    @property
    def actor(self) -> str:
        return f"{self._me.issuer}|{self._me.subject}"

    def who(self, scope: Scope, actor: str) -> UserIdentity | ServiceIdentity | None:
        return self._me if actor == DEV_ACTOR else None

    def linked(self, scope: Scope, actor: str) -> bool:
        return actor == DEV_ACTOR


# One developer plays every part on the local stack, so the floors that need two people are off.
# The committer floor, which needs no one else, stays on. Real floors come from org policy.
LOCAL_FLOORS = Floors.model_construct(single_human_allowed=True, requester_excluded_from=())


def moving_aware_gates(store: Store, policy: DecisionPolicy) -> GateService:
    """The app's gate service (D3-26): the shared builder plus the moving-subject rules. No gate
    opens on a closed ticket (``GateHooks.on_open``), and every approval pins ``MOVE#state`` in
    its own transaction (a pre-decision guard)."""
    hooks = GateHooks()
    hooks.on_open(refuse_closed_ticket)
    return build_gate_service(store, policy, hooks=hooks).with_guards(refuse_moved_subject)


def gate_policy(
    store: Store, directory: DevDirectory, *, floors: Floors = LOCAL_FLOORS
) -> GatePolicy:
    """The policy of the gate service: the gate's config, the person, the run's records and the
    floors, so a decision is refused when separation of duties bars it (D3-24)."""

    def requester_of(scope: Scope, run_id: RunId) -> str | None:
        item = store.get(scope, Key(API_INDEX, str(run_id)))
        found = item.data.get("started_by") if item else None
        return found if isinstance(found, str) else None

    return GatePolicy(
        rules=LinearGates(LINEAR_V0, default_gate_roles),
        directory=directory,
        records=StoreRecords(
            store,
            read=read_records,
            requester_of=requester_of,
            snapshot=lambda scope, gate: frozenset({directory.actor}),
        ),
        floors=floors,
        actor_key=lambda who: DEV_ACTOR,  # the dev token's one actor string is "dev"
    )


def build_local(env: Mapping[str, str] | None = None) -> FastAPI:
    """The app ``make dev`` serves. Refuses outside local mode before it opens anything."""
    env = os.environ if env is None else env
    mode = env.get("STO_MODE", "")
    if mode != "local":
        raise DevAuthRefusedError(
            f"dev auth only runs in local mode (STO_MODE=local); STO_MODE is {mode!r}"
        )
    path = Path(env.get("STO_DB", DEFAULT_DB))
    made = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if made and "STO_DB" not in env:  # only the directory this code made for itself
        keep_out_of_git(path.parent)
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
        gates=moving_aware_gates(store, gate_policy(store, DevDirectory(scope.team))),
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
            landed = land_pending(scm, landed)
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
