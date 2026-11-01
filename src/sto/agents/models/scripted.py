"""A scripted Strands ``Model``: replays a fixed list of turns through the real event loop.

The agent, its tool executor and its structured-output handling are the real Strands ones. Only
the model call is replaced, which is the one thing a hermetic test cannot make.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, AsyncIterable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from pydantic import BaseModel
from strands.models import Model
from strands.types.content import Messages
from strands.types.streaming import StreamEvent
from strands.types.tools import ToolSpec

from sto.agents.harness import OUTCOME_TOOL

T = TypeVar("T", bound=BaseModel)


@dataclass(frozen=True)
class ToolCall:
    name: str
    input: dict[str, Any]

    @classmethod
    def outcome(cls, outcome: str, summary: str) -> ToolCall:
        return cls(OUTCOME_TOOL, {"outcome": outcome, "summary": summary})


@dataclass(frozen=True)
class Turn:
    """One model response: optional text, any number of tool calls, a stop reason.

    ``error`` makes the model call itself raise (throttling, an engine error), for tests of the
    harness's failure mapping.
    """

    reply: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: str = "end_turn"
    error: BaseException | None = None

    @classmethod
    def text(cls, text: str) -> Turn:
        return cls(reply=text)

    @classmethod
    def tool_call(cls, name: str, tool_input: dict[str, Any]) -> Turn:
        return cls.tools(ToolCall(name, tool_input))

    @classmethod
    def tools(cls, *calls: ToolCall) -> Turn:
        """Several tool calls in one model response (parallel tool use)."""
        return cls(tool_calls=calls, stop_reason="tool_use")

    @classmethod
    def outcome(cls, outcome: str, summary: str) -> Turn:
        return cls.tools(ToolCall.outcome(outcome, summary))

    @classmethod
    def refusal(cls, text: str = "I can't help with that.") -> Turn:
        return cls(reply=text, stop_reason="content_filtered")

    @classmethod
    def truncated(cls, text: str) -> Turn:
        return cls(reply=text, stop_reason="max_tokens")

    @classmethod
    def raising(cls, error: BaseException) -> Turn:
        return cls(error=error)


class ScriptExhaustedError(RuntimeError):
    """The agent asked for more turns than the script has."""


TurnSource = Callable[[Messages, "list[ToolSpec] | None"], Turn]


class ScriptedModel(Model):
    """Replays ``turns`` in order, or asks ``responder`` for each turn."""

    def __init__(self, turns: Sequence[Turn] = (), *, responder: TurnSource | None = None) -> None:
        self._turns = list(turns)
        self._responder = responder
        self._config: dict[str, Any] = {"model_id": "scripted"}
        self.seen_messages: list[Messages] = []
        self._n_calls = 0

    def update_config(self, **model_config: Any) -> None:
        self._config.update(model_config)

    def get_config(self) -> Any:
        return self._config

    @property
    def calls(self) -> int:
        return self._n_calls

    @property
    def unconsumed(self) -> int:
        return max(0, len(self._turns) - self._n_calls) if self._responder is None else 0

    def assert_consumed(self) -> None:
        """Fail if the script has turns the agent never asked for."""
        if self.unconsumed:
            raise AssertionError(f"{self.unconsumed} scripted turn(s) were never consumed")

    def _next(self, messages: Messages, tool_specs: list[ToolSpec] | None) -> Turn:
        if self._responder is not None:
            return self._responder(messages, tool_specs)
        if self._n_calls >= len(self._turns):
            raise ScriptExhaustedError(
                f"script has {len(self._turns)} turns; call {self._n_calls + 1}"
            )
        return self._turns[self._n_calls]

    async def stream(
        self,
        messages: Messages,
        tool_specs: list[ToolSpec] | None = None,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> AsyncIterable[StreamEvent]:
        self.seen_messages.append(list(messages))
        turn = self._next(messages, tool_specs)
        self._n_calls += 1
        if turn.error is not None:
            raise turn.error
        yield {"messageStart": {"role": "assistant"}}
        if turn.reply:
            yield {"contentBlockStart": {"start": {}}}
            yield {"contentBlockDelta": {"delta": {"text": turn.reply}}}
            yield {"contentBlockStop": {}}
        for i, call in enumerate(turn.tool_calls):
            tool_use_id = f"scripted-{self._n_calls}-{i}"
            yield {
                "contentBlockStart": {
                    "start": {"toolUse": {"name": call.name, "toolUseId": tool_use_id}}
                }
            }
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(call.input)}}}}
            yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": turn.stop_reason}}  # type: ignore[typeddict-item]
        yield {
            "metadata": {
                "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                "metrics": {"latencyMs": 0},
            }
        }

    async def structured_output(
        self,
        output_model: type[T],
        prompt: Messages,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[dict[str, T | Any], None]:
        raise NotImplementedError("the harness uses the event loop's structured-output tool")
        yield {}  # pragma: no cover  (marks this as an async generator)
