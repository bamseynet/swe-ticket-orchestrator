"""D1-05: a real Strands ``Agent`` on a scripted model. Nothing in the framework is mocked."""

from __future__ import annotations

import pytest
from strands import Agent, tool

from sto.agents.harness import (
    OutcomeNotDeclaredError,
    RefusalError,
    StageResult,
    StepFailedError,
    run_stage,
)
from sto.agents.models.fake import FakeLLM
from sto.agents.models.scripted import ScriptedModel, Turn
from sto.domain.errors import PermanentError

OUTCOMES = ("approved", "needs_changes")


def test_structured_outcome_from_a_declared_list() -> None:
    model = ScriptedModel([Turn.outcome("approved", "looks fine")])
    result = run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert result == StageResult(outcome="approved", summary="looks fine")


def test_real_event_loop_runs_tool_then_outcome() -> None:
    calls: list[str] = []

    @tool
    def lookup(key: str) -> str:
        """Look a key up."""
        calls.append(key)
        return f"value-of-{key}"

    model = ScriptedModel(
        [Turn.tool_call("lookup", {"key": "a"}), Turn.outcome("needs_changes", "found it")]
    )
    result = run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[lookup])
    assert calls == ["a"]  # the SDK's own executor invoked the real tool
    assert result.outcome == "needs_changes"
    # The scripted model saw the tool result the SDK produced, proving a real loop ran.
    assert any("value-of-a" in str(m) for m in model.seen_messages[-1])


def test_scripted_model_is_a_strands_model_driven_by_a_plain_agent() -> None:
    model = ScriptedModel([Turn.text("hello")])
    agent = Agent(model=model, callback_handler=None)
    out = agent("hi")
    assert out.stop_reason == "end_turn"
    assert "hello" in str(out)


def test_undeclared_outcome_fails_the_step() -> None:
    model = ScriptedModel([Turn.outcome("merge_it_now", "trust me")])
    with pytest.raises(OutcomeNotDeclaredError) as exc:
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert isinstance(exc.value, StepFailedError)
    assert isinstance(exc.value, PermanentError)
    assert "merge_it_now" in str(exc.value)


def test_refusal_fails_the_step() -> None:
    model = ScriptedModel([Turn.refusal()])
    with pytest.raises(RefusalError) as exc:
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert isinstance(exc.value, StepFailedError)


def test_max_tokens_is_a_failure_not_a_result() -> None:
    model = ScriptedModel([Turn.truncated("half a dra")])
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)


def test_no_outcome_at_all_fails_the_step() -> None:
    model = ScriptedModel([Turn.text("no outcome"), Turn.text("still none")])
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)


def test_script_exhaustion_is_loud() -> None:
    model = ScriptedModel([])
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)


def test_empty_outcome_list_is_rejected() -> None:
    with pytest.raises(ValueError, match="outcomes"):
        run_stage(ScriptedModel([]), system_prompt="s", prompt="p", outcomes=())


def test_fake_llm_picks_outcome_by_keyword_and_says_it_is_fake() -> None:
    fake = FakeLLM(rules={"typo": "needs_changes"}, default="approved")
    assert "not real analysis" in FakeLLM.__doc__.lower()  # type: ignore[union-attr]
    r1 = run_stage(fake, system_prompt="s", prompt="there is a typo here", outcomes=OUTCOMES)
    r2 = run_stage(fake, system_prompt="s", prompt="all good", outcomes=OUTCOMES)
    assert r1.outcome == "needs_changes"
    assert r2.outcome == "approved"
    assert "simulated" in r1.summary.lower()


def test_fake_llm_default_outside_declared_list_fails() -> None:
    fake = FakeLLM(rules={}, default="bogus")
    with pytest.raises(OutcomeNotDeclaredError):
        run_stage(fake, system_prompt="s", prompt="x", outcomes=OUTCOMES)
