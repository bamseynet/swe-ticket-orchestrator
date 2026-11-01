"""Minimal stage harness (D1-05): run a real Strands ``Agent`` and return a validated outcome.

The model must finish by filling ``StageOutcome``. Code, not the model, checks that the outcome is
in the stage's declared list. Anything else fails the step (PLAN 8.1, invariant A6).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from strands import Agent
from strands.models import Model
from strands.types.agent import Limits
from strands.types.content import Messages
from strands.types.exceptions import EventLoopException, ModelThrottledException

from sto.domain.errors import PermanentError, StoError, TransientError

_REFUSAL_STOPS = frozenset({"content_filtered", "guardrail_intervened"})
# "tool_use" is how Strands reports a structured outcome delivered through its outcome tool;
# "end_turn" is the forced-JSON-text path. Everything else (max_tokens, interrupt, cancelled,
# every limit_*) is a failure, so this is an allow-list.
_OK_STOPS = frozenset({"tool_use", "end_turn"})

# D5-01 owns the real per-stage limits. These stop a runaway loop in the meantime.
# PLAN 8.1 says structured outcomes get "one retry", so two attempts. No single SDK value gives
# one retry on every path: malformed outcome-tool input gets one retry (2 calls), but text-only
# turns get two (text, text, then an outcome succeeds on call 3). Accepted: both are bounded.
_LIMITS: Limits = {"structured_output_attempts": 2, "turns": 10}


class StageOutcome(BaseModel):
    """What the model must return: one outcome and a short summary."""

    model_config = ConfigDict(extra="forbid")

    outcome: str = Field(description="One outcome from the declared list")
    summary: str = Field(min_length=1, description="Short plain-text reason")

    @field_validator("summary")
    @classmethod
    def _summary_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("summary must not be blank")
        return value


OUTCOME_TOOL = StageOutcome.__name__  # Strands names the outcome tool after the model class


@dataclass(frozen=True)
class StageResult:
    outcome: str
    summary: str


class StepFailedError(PermanentError):
    """The step failed. Permanent: only a person's audited Retry re-runs it."""


class StepThrottledError(TransientError):
    pass


class OutcomeNotDeclaredError(StepFailedError):
    pass


class RefusalError(StepFailedError):
    pass


def _check_final_tool_turn(messages: Messages) -> None:
    """When the run ended on a tool turn, the outcome must have been its only tool call.

    Strands runs every tool in a turn and still returns the structured output, so a sibling tool
    that raised, or was unknown, would otherwise be silently dropped. (A sibling that interrupts
    is caught earlier, by the stop-reason allow-list.) An error result from an *earlier* turn is
    allowed: the model saw it, and D5 owns degraded runs. If the last message is the assistant's
    (the forced-text path), there is no tool turn to check.
    """
    if not messages or messages[-1]["role"] != "user":
        return
    uses = [b["toolUse"]["name"] for b in messages[-2]["content"] if "toolUse" in b]
    if uses != [OUTCOME_TOOL]:
        raise StepFailedError(f"the outcome must be the only tool call in its turn; got {uses}")


def run_stage(
    model: Model,
    *,
    system_prompt: str,
    prompt: str,
    outcomes: Sequence[str],
    tools: Sequence[Any] = (),
) -> StageResult:
    if not isinstance(model, Model):
        # Agent(model=None) builds a BedrockModel, which reaches for ambient AWS credentials.
        raise TypeError(f"model must be a strands Model, got {type(model).__name__}")
    if not outcomes:
        raise ValueError("outcomes must list at least one declared outcome")
    declared = tuple(outcomes)
    agent = Agent(
        model=model,
        system_prompt=f"{system_prompt}\n\nDeclared outcomes: {', '.join(declared)}",
        tools=list(tools),
        callback_handler=None,
        retry_strategy=None,  # one retry layer only, and it belongs to the engine (PLAN 6.2)
    )
    try:
        result = agent(prompt, structured_output_model=StageOutcome, limits=_LIMITS)
    except Exception as exc:
        # From the second model call on, the SDK wraps errors in EventLoopException.
        cause = exc.original_exception if isinstance(exc, EventLoopException) else exc
        if isinstance(cause, StoError):
            # Already classified (D2-10 owns the full table). Note a PermanentError raised inside
            # a *tool* never gets here: the SDK turns it into an error result, the model sees it,
            # and may still return an outcome (D5 decides how that should count).
            raise cause from None
        if isinstance(cause, ModelThrottledException):
            raise StepThrottledError(f"model throttled: {cause}") from cause
        raise StepFailedError(f"agent run failed: {type(cause).__name__}: {cause}") from cause

    if result.stop_reason in _REFUSAL_STOPS:
        raise RefusalError(f"model refused (stop reason {result.stop_reason})")
    if result.stop_reason not in _OK_STOPS:
        raise StepFailedError(
            f"step did not finish with an outcome (stop reason {result.stop_reason}); "
            "a limit, truncation or interruption is never a usable result"
        )
    out = result.structured_output
    if not isinstance(out, StageOutcome):
        raise StepFailedError(f"no structured outcome returned (stop reason {result.stop_reason})")
    _check_final_tool_turn(agent.messages)
    if out.outcome not in declared:
        raise OutcomeNotDeclaredError(
            f"outcome {out.outcome!r} is not declared; expected one of {list(declared)}"
        )
    return StageResult(outcome=out.outcome, summary=out.summary)
