"""Runs and their events (D1-08). Everything here records something durable and returns; the
work itself is driven in the background (``Runtime.kick``)."""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from sto.api.runtime import (
    RunFinishedError,
    RunNotFoundError,
    Runtime,
    StoreConflictError,
)
from sto.domain import RunId
from sto.domain.errors import InvalidIdError

router = APIRouter(tags=["runs"])


class ApiError(Exception):
    """An error with a stable ``code``; rendered as ``{"error": {"code", "message", ...}}``."""

    def __init__(
        self,
        http_status: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.http_status, self.code, self.message = http_status, code, message
        self.headers, self.extra = headers or {}, extra or {}
        super().__init__(message)


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody


def get_runtime(request: Request) -> Runtime:
    runtime: Runtime = request.app.state.runtime
    return runtime


RuntimeDep = Annotated[Runtime, Depends(get_runtime)]
NOT_FOUND: dict[int | str, dict[str, Any]] = {404: {"model": ErrorResponse}}


def parse_run_id(text: str) -> RunId:
    try:
        return RunId.parse(text)
    except (ValueError, TypeError, InvalidIdError):
        raise ApiError(404, "run_not_found", f"no run {text!r}") from None


class NewRun(BaseModel):
    ticket: str | None = Field(default=None, max_length=200, description="The ticket's key.")


class RunOut(BaseModel):
    id: str
    status: str
    stage: str | None
    blocked_reason: str | None
    ticket: str | None
    held: str | None = Field(description="Why the driver stopped on a command it cannot run.")
    driver_error: str | None = Field(description="The error that ended the last drive, if any.")


class RunPage(BaseModel):
    runs: list[RunOut]
    cursor: str | None


class EventOut(BaseModel):
    seq: int
    type: str
    outcome: str = Field(description="applied, or why the run refused it")
    data: dict[str, Any]
    status: str
    stage: str | None
    detail: str


class EventPage(BaseModel):
    events: list[EventOut]
    cursor: str | None = Field(description="Pass as `after` to get what comes next.")


@router.post(
    "/runs",
    status_code=202,
    response_model=RunOut,
    summary="Start a run",
    description="Accepted: the run is queued and driven in the background.",
)
async def create_run(body: NewRun, rt: RuntimeDep) -> dict[str, Any]:
    try:
        run = await rt.create_run(body.ticket)
    except StoreConflictError as e:
        raise _busy(e) from e
    return await rt.get_run(run.id)


@router.get("/runs", response_model=RunPage, summary="List runs")
async def list_runs(
    rt: RuntimeDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    try:
        runs, nxt = await rt.list_runs(limit, cursor)
    except ValueError:
        raise ApiError(422, "bad_cursor", "that cursor is not valid") from None
    except StoreConflictError as e:
        raise _busy(e) from e
    return {"runs": runs, "cursor": nxt}


@router.get("/runs/{run_id}", response_model=RunOut, responses=NOT_FOUND, summary="One run")
async def get_run(run_id: str, rt: RuntimeDep) -> dict[str, Any]:
    try:
        return await rt.get_run(parse_run_id(run_id))
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e


_CURSOR = re.compile(r"e(0|[1-9][0-9]{0,11})")


@router.get(
    "/runs/{run_id}/events",
    response_model=EventPage,
    responses=NOT_FOUND,
    summary="The run's timeline, resumable",
    description=(
        "Events in order. Pass the returned `cursor` as `after` to get only what is newer; at "
        "the end the same cursor comes back, so polling never repeats or skips an event."
    ),
)
async def events(
    run_id: str,
    rt: RuntimeDep,
    after: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    seq = -1
    if after is not None:
        m = _CURSOR.fullmatch(after)
        if m is None:
            raise ApiError(422, "bad_cursor", "that cursor is not valid")
        seq = int(m.group(1))
    try:
        found = await rt.events(parse_run_id(run_id), seq, limit)
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e
    except StoreConflictError as e:
        raise _busy(e) from e
    cursor = f"e{found[-1]['seq']}" if found else after
    return {"events": found, "cursor": cursor}


@router.post(
    "/runs/{run_id}/cancel",
    status_code=202,
    response_model=RunOut,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
    summary="Stop a run",
    description="Accepted: the Stop is applied in the background, ahead of any waiting backoff.",
)
async def cancel(run_id: str, rt: RuntimeDep) -> dict[str, Any]:
    rid = parse_run_id(run_id)
    try:
        await rt.cancel(rid)
        return await rt.get_run(rid)
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e
    except RunFinishedError as e:
        raise ApiError(409, "run_finished", str(e)) from e


def _busy(e: Exception) -> ApiError:
    return ApiError(503, "store_conflict", str(e), headers={"Retry-After": "1"})
