"""Gates and decisions (D1-08). A decision goes through the one decision function of the gate
service (ADR-0005 #7); this file only maps its answers to HTTP."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Path
from pydantic import BaseModel, Field

from sto.api.routers.runs import (
    NOT_FOUND,
    ApiError,
    ErrorResponse,
    RuntimeDep,
    _busy,
    parse_run_id,
)
from sto.api.runtime import DeliveryFailedError, RunNotFoundError, StoreConflictError
from sto.domain import DecisionKind, Gate, Surface, TransientError
from sto.gates.service import (
    DecisionNotAllowedError,
    GateClosedError,
    GateConflictError,
    GateError,
    GateNotFoundError,
    GateRoundLimitError,
    StaleRoundError,
    StaleSubjectError,
)
from sto.store.ports import ConditionFailedError

log = logging.getLogger("sto.api")
router = APIRouter(tags=["gates"])

_RETRY = {"Retry-After": "1"}
ACTOR = "dev"  # the dev token has one identity


class GateOut(BaseModel):
    id: str
    name: str
    round: int
    type: str
    status: str
    closed_by: str | None
    subject_digest: str = Field(description="Send this back with an approval: the subject seen.")
    head_sha: str | None


class GateList(BaseModel):
    gates: list[GateOut]


class DecisionIn(BaseModel):
    kind: DecisionKind
    subject_digest: str = Field(
        default="",
        max_length=200,
        description="The subject seen. Required for `approve`; a veto does not need it.",
    )
    comment: str = Field(
        default="",
        max_length=10_000,
        description="Required (not blank) for every kind except `approve`: a veto says why.",
    )


class DecisionOut(BaseModel):
    decision_id: str
    gate: GateOut


def gate_out(g: Gate) -> dict[str, Any]:
    return {
        "id": str(g.id),
        "name": g.name,
        "round": g.round,
        "type": g.type.value,
        "status": g.status.value,
        "closed_by": g.closed_by,
        "subject_digest": g.subject.digest(),
        "head_sha": g.subject.head_sha,
    }


@router.get(
    "/runs/{run_id}/gates",
    response_model=GateList,
    responses=NOT_FOUND,
    summary="The run's gates, every round",
)
async def list_gates(run_id: str, rt: RuntimeDep) -> dict[str, Any]:
    try:
        gates = await rt.gates(parse_run_id(run_id))
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e
    except StoreConflictError as e:
        raise _busy(e) from e
    return {"gates": [gate_out(g) for g in gates]}


_REFUSALS: list[tuple[type[GateError], int]] = [
    (GateNotFoundError, 404),
    (GateClosedError, 409),
    (StaleSubjectError, 409),
    (StaleRoundError, 409),
    (GateConflictError, 409),
    (DecisionNotAllowedError, 422),
    (GateRoundLimitError, 422),
]


@router.post(
    "/runs/{run_id}/gates/{name}/{round}/decisions",
    status_code=202,
    response_model=DecisionOut,
    responses={
        404: {"model": ErrorResponse, "description": "No such run or gate."},
        409: {
            "model": ErrorResponse,
            "description": "The gate is closed (`gate_closed`, with who closed it), or the "
            "subject or round is stale.",
        },
        422: {
            "model": ErrorResponse,
            "description": "That decision is not available here, or a comment is required "
            "(`comment_required`: every kind but `approve` needs a non-blank comment).",
        },
        503: {
            "model": ErrorResponse,
            "description": "Busy, or the decision is recorded but not yet delivered to the run "
            "(`delivery_failed`, `decision_recorded`): repeat the request to finish it.",
        },
    },
    summary="Decide a gate",
    description=(
        "Accepted: the gate is closed now; the run moves on in the background. A comment is "
        "required for every kind except `approve`. Deciding a gate of a run that was already "
        "stopped closes the gate but changes nothing else (closing gates on Stop is D2-11)."
    ),
)
async def decide(
    run_id: str,
    name: Annotated[str, Path(min_length=1, max_length=200)],
    round: Annotated[int, Path(ge=1, le=1000)],
    body: DecisionIn,
    rt: RuntimeDep,
) -> Any:
    if body.kind is not DecisionKind.APPROVE and not body.comment.strip():
        raise ApiError(422, "comment_required", f"a {body.kind.value} decision needs a comment")
    if not body.kind.is_negative and not body.subject_digest.strip():
        raise ApiError(
            422, "subject_digest_required", f"a {body.kind.value} decision needs the subject seen"
        )
    try:
        decided = await rt.decide(
            parse_run_id(run_id),
            name,
            round,
            body.kind,
            actor=ACTOR,
            surface=Surface.UI,
            subject_digest=body.subject_digest,
            comment=body.comment,
        )
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e
    except DeliveryFailedError as e:
        raise ApiError(
            503,
            "delivery_failed",
            str(e),
            headers={"Retry-After": "1"},
            extra={"decision_recorded": True},
        ) from e
    except StoreConflictError as e:
        raise _busy(e) from e
    except GateClosedError as e:
        extra: dict[str, Any] = {
            "gate": e.gate_name,
            "round": e.round,
            "status": e.status.value,
            "closed_by": e.closed_by,
        }
        try:
            stop_offered = await rt.can_stop(parse_run_id(run_id))
        except Exception as stop_error:  # the 409 is true whether or not we can say who can stop
            log.warning("could not tell whether run %s can be stopped: %r", run_id, stop_error)
            stop_offered = False
        if stop_offered:
            extra["stop"] = {"method": "POST", "href": f"/runs/{run_id}/cancel"}
        raise ApiError(
            409,
            e.code,
            str(e),
            extra=extra,
        ) from e
    except GateError as e:
        for kind, status in _REFUSALS:
            if isinstance(e, kind):
                raise ApiError(status, e.code, str(e)) from e
        raise ApiError(400, e.code, str(e)) from e
    except (ValueError, TypeError) as e:
        # Every field of the request is checked above, so this is stored data the domain
        # refuses (a corrupt gate): a server fault, logged here and not described to the client.
        log.error("deciding gate %s of run %s hit corrupt data: %r", name, run_id, e, exc_info=e)
        raise ApiError(500, "internal_error", "the server could not process this request") from e
    except ConditionFailedError as e:
        # The gate service ran out of retries on a gate that is still open (D3-06 reworks this).
        raise ApiError(
            503, "gate_contention", "the gate kept changing; try again", headers=_RETRY
        ) from e
    except TransientError as e:  # the gate kept changing under the call
        raise ApiError(503, "gate_contention", str(e), headers=_RETRY) from e
    return {"decision_id": str(decided.decision.id), "gate": gate_out(decided.gate)}
