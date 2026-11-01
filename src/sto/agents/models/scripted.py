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

T = TypeVar("T", bound=BaseModel)

OUTCOME_TOOL = "StageOutcome"  # name of the pydantic model the harness asks Strands to fill


@dataclass(frozen=True)
class Turn:
    """One model response: text and/or one tool call, ended with ``stop_reason``."""

    reply: str = ""
    tool_name: str | None = None
    tool_input: dict[str, Any] | None = None
    stop_reason: str = "end_turn"

    @classmethod
    def text(cls, text: str) -> Turn:
        return cls(reply=text)

    @classmethod
    def tool_call(cls, name: str, tool_input: dict[str, Any]) -> Turn:
        return cls(tool_name=name, tool_input=tool_input, stop_reason="tool_use")

    @classmethod
    def outcome(cls, outcome: str, summary: str) -> Turn:
        return cls.tool_call(OUTCOME_TOOL, {"outcome": outcome, "summary": summary})

    @classmethod
    def refusal(cls, text: str = "I can't help with that.") -> Turn:
        return cls(reply=text, stop_reason="content_filtered")

    @classmethod
    def truncated(cls, text: str) -> Turn:
        return cls(reply=text, stop_reason="max_tokens")


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
        yield {"messageStart": {"role": "assistant"}}
        if turn.reply:
            yield {"contentBlockStart": {"start": {}}}
            yield {"contentBlockDelta": {"delta": {"text": turn.reply}}}
            yield {"contentBlockStop": {}}
        if turn.tool_name is not None:
            yield {
                "contentBlockStart": {
                    "start": {
                        "toolUse": {
                            "name": turn.tool_name,
                            "toolUseId": f"scripted-{self._n_calls}",
                        }
                    }
                }
            }
            payload = json.dumps(turn.tool_input or {})
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": payload}}}}
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
