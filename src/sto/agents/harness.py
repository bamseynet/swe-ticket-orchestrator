"""Minimal stage harness (D1-05): run a real Strands ``Agent`` and return a validated outcome.

The model must finish by filling ``StageOutcome``. Code, not the model, checks that the outcome is
in the stage's declared list. Anything else fails the step (PLAN 8.1, invariant A6).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field
from strands import Agent
from strands.models import Model

from sto.domain.errors import PermanentError

_FAILURE_STOPS = {"content_filtered", "guardrail_intervened"}


class StageOutcome(BaseModel):
    """What the model must return: one outcome and a short summary."""

    outcome: str = Field(description="One outcome from the declared list")
    summary: str = Field(description="Short plain-text reason")


@dataclass(frozen=True)
class StageResult:
    outcome: str
    summary: str


class StepFailedError(PermanentError):
    """The step failed. Permanent: only a person's audited Retry re-runs it."""


class OutcomeNotDeclaredError(StepFailedError):
    pass


class RefusalError(StepFailedError):
    pass


def run_stage(
    model: Model,
    *,
    system_prompt: str,
    prompt: str,
    outcomes: Sequence[str],
    tools: Sequence[Any] = (),
) -> StageResult:
    if not outcomes:
        raise ValueError("outcomes must list at least one declared outcome")
    declared = tuple(outcomes)
    agent = Agent(
        model=model,
        system_prompt=f"{system_prompt}\n\nDeclared outcomes: {', '.join(declared)}",
        tools=list(tools),
        callback_handler=None,
    )
    try:
        result = agent(prompt, structured_output_model=StageOutcome)
    except Exception as exc:
        raise StepFailedError(f"agent run failed: {type(exc).__name__}: {exc}") from exc

    if result.stop_reason in _FAILURE_STOPS:
        raise RefusalError(f"model refused (stop reason {result.stop_reason})")
    if result.stop_reason == "max_tokens":
        raise StepFailedError("model hit max_tokens; a truncated result is never usable")
    out = result.structured_output
    if not isinstance(out, StageOutcome):
        raise StepFailedError(f"no structured outcome returned (stop reason {result.stop_reason})")
    if out.outcome not in declared:
        raise OutcomeNotDeclaredError(
            f"outcome {out.outcome!r} is not declared; expected one of {list(declared)}"
        )
    return StageResult(outcome=out.outcome, summary=out.summary)
