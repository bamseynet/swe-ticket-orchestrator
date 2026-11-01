"""D1-05: a real Strands ``Agent`` on a scripted model. Nothing in the framework is mocked."""

from __future__ import annotations

import pytest
from strands import Agent, ToolContext, tool
from strands.types.exceptions import ModelThrottledException

from sto.agents.harness import (
    OUTCOME_TOOL,
    OutcomeNotDeclaredError,
    RefusalError,
    StageOutcome,
    StageResult,
    StepFailedError,
    StepThrottledError,
    run_stage,
)
from sto.agents.models.fake import FakeLLM
from sto.agents.models.scripted import ScriptedModel, ScriptExhaustedError, ToolCall, Turn
from sto.domain.errors import PermanentError, TransientError

OUTCOMES = ("approved", "needs_changes")
NO_OUTCOME_CALLS = 3  # text-only turns get two retries; see the comment on _LIMITS


def test_structured_outcome_from_a_declared_list() -> None:
    model = ScriptedModel([Turn.outcome("approved", "looks fine")])
    result = run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert result == StageResult(outcome="approved", summary="looks fine")
    model.assert_consumed()


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
    model = ScriptedModel([Turn.text("no outcome")] * 20)
    with pytest.raises(StepFailedError, match="limit"):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert model.calls == NO_OUTCOME_CALLS  # the limit stopped it, not script exhaustion


def test_script_exhaustion_is_loud() -> None:
    model = ScriptedModel([])
    with pytest.raises(StepFailedError) as exc:
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert isinstance(exc.value.__cause__, ScriptExhaustedError)


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


# --- review pass 1 ---------------------------------------------------------------------------


@tool
def boom() -> str:
    """Always raises."""
    raise RuntimeError("tool exploded")


@tool
def fine() -> str:
    """Always works."""
    return "ok"


@tool(context=True)
def pauses(tool_context: ToolContext) -> str:
    """Interrupts for a human."""
    return str(tool_context.interrupt("need-human", reason="please look"))


def _outcome_with(*siblings: ToolCall, outcome: str = "approved") -> ScriptedModel:
    return ScriptedModel([Turn.tools(*siblings, ToolCall.outcome(outcome, "all tests passed"))])


def test_outcome_beside_a_failing_tool_in_the_same_turn_fails() -> None:
    model = _outcome_with(ToolCall("boom", {}))
    with pytest.raises(StepFailedError, match="tool"):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[boom])


def test_outcome_beside_an_unknown_tool_in_the_same_turn_fails() -> None:
    model = _outcome_with(ToolCall("nope", {}))
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)


def test_outcome_beside_an_interrupting_tool_fails() -> None:
    model = _outcome_with(ToolCall("pauses", {}))
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[pauses])


def test_outcome_beside_a_healthy_tool_in_the_same_turn_still_fails() -> None:
    # The model answered before it saw this tool's result, so the outcome is not grounded in it.
    model = _outcome_with(ToolCall("fine", {}))
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[fine])


def test_outcome_after_an_error_result_the_model_saw_is_allowed() -> None:
    # D5 owns degraded-run handling; here the model saw the failure and chose an outcome.
    model = ScriptedModel([Turn.tool_call("boom", {}), Turn.outcome("needs_changes", "tool broke")])
    result = run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[boom])
    assert result.outcome == "needs_changes"
    model.assert_consumed()


def test_two_outcomes_in_one_turn_fail() -> None:
    model = ScriptedModel(
        [Turn.tools(ToolCall.outcome("approved", "a"), ToolCall.outcome("needs_changes", "b"))]
    )
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)


def test_endless_malformed_outcomes_stop_after_one_retry() -> None:
    bad = Turn.tool_call(OUTCOME_TOOL, {"outcome": 7})
    model = ScriptedModel([bad] * 300)
    with pytest.raises(StepFailedError):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert model.calls == 2  # first attempt plus exactly one retry


def test_a_tool_loop_hits_the_turn_limit_and_fails() -> None:
    model = ScriptedModel([Turn.tool_call("fine", {})] * 200)
    with pytest.raises(StepFailedError, match="limit"):
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[fine])
    assert model.calls == 10  # the turn limit, exactly


@pytest.mark.parametrize(
    "stop", ["content_filtered", "guardrail_intervened", "max_tokens", "cancelled"]
)
def test_a_bad_stop_reason_beats_an_outcome_in_the_same_turn(stop: str) -> None:
    from dataclasses import replace

    turn = replace(Turn.outcome("approved", "fine"), stop_reason=stop)
    with pytest.raises(StepFailedError):
        run_stage(ScriptedModel([turn]), system_prompt="s", prompt="p", outcomes=OUTCOMES)


def test_refusal_is_a_refusal_error_for_guardrail_stops() -> None:
    from dataclasses import replace

    turn = replace(Turn.refusal(), stop_reason="guardrail_intervened")
    with pytest.raises(RefusalError):
        run_stage(ScriptedModel([turn]), system_prompt="s", prompt="p", outcomes=OUTCOMES)


def test_throttling_is_transient_and_not_retried_inside_the_harness() -> None:
    model = ScriptedModel([Turn.raising(ModelThrottledException("slow down"))] * 5)
    with pytest.raises(StepThrottledError) as exc:
        run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    assert isinstance(exc.value, TransientError)
    assert not isinstance(exc.value, PermanentError)
    assert model.calls == 1  # one retry layer only, and it is the engine's


def test_an_sto_error_raised_in_the_run_passes_through_unchanged() -> None:
    err = TransientError("budget service busy")
    with pytest.raises(TransientError) as exc:
        run_stage(
            ScriptedModel([Turn.raising(err)]), system_prompt="s", prompt="p", outcomes=OUTCOMES
        )
    assert exc.value is err


def test_model_none_is_refused_before_strands_builds_an_ambient_bedrock_model() -> None:
    with pytest.raises(TypeError, match="model"):
        run_stage(None, system_prompt="s", prompt="p", outcomes=OUTCOMES)  # type: ignore[arg-type]


def test_unconsumed_turns_are_reported() -> None:
    model = ScriptedModel([Turn.outcome("approved", "x"), Turn.text("never used")])
    run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES)
    with pytest.raises(AssertionError, match="never consumed"):
        model.assert_consumed()


def test_stage_outcome_rejects_extra_fields_and_empty_summary() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        StageOutcome.model_validate({"outcome": "approved", "summary": "x", "extra": 1})
    with pytest.raises(ValidationError):
        StageOutcome(outcome="approved", summary="")
    with pytest.raises(ValidationError):
        StageOutcome(outcome="approved", summary="  \n\t ")


def test_outcome_tool_name_is_derived_from_the_model_class() -> None:
    assert StageOutcome.__name__ == OUTCOME_TOOL


# --- review pass 2: errors raised after the first model call are wrapped by the SDK ---------------

_THROTTLE = ModelThrottledException("slow down")
_STO = TransientError("budget service busy")
_MALFORMED = Turn.tool_call(OUTCOME_TOOL, {"outcome": 7})


@pytest.mark.parametrize(
    "script_before",
    [
        pytest.param([Turn.tool_call("fine", {})], id="after-a-tool"),
        pytest.param([_MALFORMED], id="after-malformed-output"),
        pytest.param([Turn.text("no outcome")], id="on-the-forced-retry"),
    ],
)
class TestErrorsOnLaterCalls:
    def test_throttling_stays_transient(self, script_before: list[Turn]) -> None:
        model = ScriptedModel([*script_before, Turn.raising(_THROTTLE)])
        with pytest.raises(StepThrottledError):
            run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[fine])
        assert model.calls == 2

    def test_sto_error_passes_through_unchanged(self, script_before: list[Turn]) -> None:
        model = ScriptedModel([*script_before, Turn.raising(_STO)])
        with pytest.raises(TransientError) as exc:
            run_stage(model, system_prompt="s", prompt="p", outcomes=OUTCOMES, tools=[fine])
        assert exc.value is _STO
