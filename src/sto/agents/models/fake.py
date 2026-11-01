"""``FakeLLM``: the demo model.

NOT REAL ANALYSIS. It matches keywords in the latest user message and returns a fixed outcome.
It exists so the local demo can run a stage with no credentials and no network. Every summary it
writes says it is simulated.
"""

from __future__ import annotations

from collections.abc import Mapping

from strands.types.content import Messages
from strands.types.tools import ToolSpec

from sto.agents.models.scripted import ScriptedModel, Turn


def _last_user_text(messages: Messages) -> str:
    for message in reversed(messages):
        if message["role"] != "user":
            continue
        parts = [block["text"] for block in message["content"] if "text" in block]
        if parts:
            return " ".join(parts)
    return ""


class FakeLLM(ScriptedModel):
    """Keyword rules, not analysis. NOT REAL ANALYSIS: the outcome depends only on which keyword
    appears in the prompt, and the summary is labelled simulated.

    ``rules`` maps a lowercase keyword to an outcome; the first match in insertion order wins,
    otherwise ``default``. The harness still validates the outcome against the declared list.
    """

    def __init__(self, rules: Mapping[str, str], default: str) -> None:
        self._rules = {k.lower(): v for k, v in rules.items()}
        self._default = default
        super().__init__(responder=self._respond)

    def _respond(self, messages: Messages, tool_specs: list[ToolSpec] | None) -> Turn:
        prompt = _last_user_text(messages).lower()
        outcome = next((o for kw, o in self._rules.items() if kw in prompt), self._default)
        return Turn.outcome(outcome, "Simulated by FakeLLM keyword rules; not real analysis.")

    def __repr__(self) -> str:
        return f"FakeLLM(rules={self._rules!r}, default={self._default!r}) # not real analysis"


__all__ = ["FakeLLM"]
