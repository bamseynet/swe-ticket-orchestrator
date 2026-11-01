"""Minimal stage harness (D1-05): run a real Strands ``Agent`` and return a validated outcome.

The model must finish by filling ``StageOutcome``. Code, not the model, checks that the outcome is
in the stage's declared list. Anything else fails the step (PLAN 8.1, invariant A6).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from strands import Agent
from strands.models import Model
from strands.types.agent import Limits
from strands.types.content import Messages
from strands.types.exceptions import ModelThrottledException

from sto.domain.errors import PermanentError, StoError, TransientError

_REFUSAL_STOPS = frozenset({"content_filtered", "guardrail_intervened"})
# "tool_use" is how Strands reports a structured outcome delivered through its outcome tool;
# "end_turn" is the forced-JSON-text path. Everything else (max_tokens, interrupt, cancelled,
# every limit_*) is a failure, so this is an allow-list.
_OK_STOPS = frozenset({"tool_use", "end_turn"})

# D5-01 owns the real per-stage limits. These stop a runaway loop in the meantime.
# PLAN 8.1: structured outcomes get "one retry", so two attempts.
_LIMITS: Limits = {"structured_output_attempts": 2, "turns": 10}


class StageOutcome(BaseModel):
    """What the model must return: one outcome and a short summary."""

    model_config = ConfigDict(extra="forbid")

    outcome: str = Field(description="One outcome from the declared list")
    summary: str = Field(min_length=1, description="Short plain-text reason")


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
    """The outcome must be the model's only action in its last turn, and nothing may have failed.

    Strands runs every tool in a turn and still returns the structured output, so a sibling tool
    that raised, was unknown or interrupted would otherwise be silently dropped. An error result
    from an *earlier* turn is allowed: the model saw it (D5 owns degraded runs).
    """
    if not messages or messages[-1]["role"] != "user":
        return  # forced-text path: the last message is the assistant's, with no tool calls
    results = [b["toolResult"] for b in messages[-1]["content"] if "toolResult" in b]
    uses = [b["toolUse"] for b in messages[-2]["content"] if "toolUse" in b]
    if [u["name"] for u in uses] != [OUTCOME_TOOL]:
        names = [u["name"] for u in uses]
        raise StepFailedError(f"the outcome must be the only tool call in its turn; got {names}")
    if any(r["status"] != "success" for r in results):
        raise StepFailedError("a tool result in the outcome's turn was not a success")


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
    except StoError:
        raise  # already classified; D2-10 owns the full classification table
    except ModelThrottledException as exc:
        raise StepThrottledError(f"model throttled: {exc}") from exc
    except Exception as exc:
        raise StepFailedError(f"agent run failed: {type(exc).__name__}: {exc}") from exc

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
