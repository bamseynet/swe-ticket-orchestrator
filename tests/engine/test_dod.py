"""D2-16: definition-of-done checks. Fixtures are synthetic; nothing here touches a network.

Missing or unreadable evidence is not done: every ``None`` below means "the driver could not
read it", and each check must fail closed on it.
"""

from __future__ import annotations

import math

import pytest

from sto.config.schema import DefinitionOfDone
from sto.domain import BLOCKED_REASONS
from sto.engine.handlers import dod
from sto.engine.handlers.dod import CheckStatus, DodFacts, Finding, evaluate, refusal

SHA = "a" * 40
OTHER = "b" * 40


def _facts(**kw: object) -> DodFacts:
    base: dict[str, object] = {
        "head_sha": SHA,
        "acceptance_criteria": ("it works",),
        "check_sha": SHA,
        "check_results": (CheckStatus("build", "passed"),),
        "required_checks": (),
        "coverage": 90.0,
        "findings": (),
    }
    return DodFacts(**{**base, **kw})  # type: ignore[arg-type]


def _dod(check: str, value: object = None, stage: str = "g") -> DefinitionOfDone:
    kw = {} if value is None else {"value": value}
    return DefinitionOfDone(stage=stage, check=check, **kw)  # type: ignore[arg-type]


def _reasons(check: str, value: object, facts: DodFacts) -> list[str]:
    return [f.reason for f in evaluate((_dod(check, value),), "g", facts)]


def test_registry_has_exactly_the_four_named_checks() -> None:
    assert set(dod.CHECKS) == {
        "ac_present",
        "checks_green",
        "coverage_at_least",
        "no_findings_above",
    }


def test_registry_covers_every_check_the_schema_allows() -> None:
    from typing import get_args

    assert set(dod.CHECKS) == set(get_args(DefinitionOfDone.model_fields["check"].annotation))


# --- ac_present ---------------------------------------------------------------------------


def test_ac_present_passes_with_a_criterion() -> None:
    assert _reasons("ac_present", None, _facts()) == []


@pytest.mark.parametrize("ac", [None, (), ("",), ("   ", "\n")])
def test_ac_present_fails_closed_without_a_real_criterion(ac: object) -> None:
    (why,) = _reasons("ac_present", None, _facts(acceptance_criteria=ac))
    assert "acceptance criteria" in why


def test_ac_present_one_blank_among_real_is_fine() -> None:
    assert _reasons("ac_present", None, _facts(acceptance_criteria=("", "real"))) == []


# --- checks_green -------------------------------------------------------------------------


def test_checks_green_passes_with_passed_and_neutral() -> None:
    res = (CheckStatus("a", "passed"), CheckStatus("b", "neutral"))
    assert _reasons("checks_green", None, _facts(check_results=res)) == []


def test_checks_green_names_each_failing_and_pending_check() -> None:
    res = (
        CheckStatus("lint", "failed"),
        CheckStatus("e2e", "pending"),
        CheckStatus("ok", "passed"),
    )
    (why,) = _reasons("checks_green", None, _facts(check_results=res))
    assert "lint" in why
    assert "e2e" in why
    assert "ok" not in why
    assert "failed" in why
    assert "pending" in why


@pytest.mark.parametrize("res", [None, ()])
def test_checks_green_fails_closed_without_results(res: object) -> None:
    (why,) = _reasons("checks_green", None, _facts(check_results=res))
    assert "no check results" in why


def test_checks_green_unknown_status_is_not_green() -> None:
    (why,) = _reasons("checks_green", None, _facts(check_results=(CheckStatus("x", "weird"),)))
    assert "x" in why


def test_checks_green_results_for_another_sha_are_stale() -> None:
    (why,) = _reasons("checks_green", None, _facts(check_sha=OTHER))
    assert "stale" in why
    assert OTHER[:7] in why
    assert SHA[:7] in why


@pytest.mark.parametrize("kw", [{"check_sha": None}, {"head_sha": None}])
def test_checks_green_needs_both_shas(kw: dict[str, object]) -> None:
    assert _reasons("checks_green", None, _facts(**kw))


def test_checks_green_required_check_missing() -> None:
    f = _facts(required_checks=("build", "security"))
    (why,) = _reasons("checks_green", None, f)
    assert "security" in why
    assert "missing" in why


def test_checks_green_name_with_two_statuses_is_not_green() -> None:
    res = (CheckStatus("a", "passed"), CheckStatus("a", "failed"))
    (why,) = _reasons("checks_green", None, _facts(check_results=res))
    assert "a" in why


# --- coverage_at_least --------------------------------------------------------------------


@pytest.mark.parametrize(("cov", "need"), [(80, 80), (80.5, 80), (100, 100), (0, 0)])
def test_coverage_at_least_passes_at_or_above(cov: float, need: float) -> None:
    assert _reasons("coverage_at_least", need, _facts(coverage=cov)) == []


def test_coverage_below_threshold_says_both_numbers() -> None:
    (why,) = _reasons("coverage_at_least", 80, _facts(coverage=79.9))
    assert "79.9" in why
    assert "80" in why


@pytest.mark.parametrize("cov", [None, math.nan, math.inf, -math.inf, True, "90", -1.0, 100.5])
def test_coverage_unreadable_or_impossible_fails_closed(cov: object) -> None:
    (why,) = _reasons("coverage_at_least", 0, _facts(coverage=cov))
    assert "coverage" in why


@pytest.mark.parametrize("bad", [None, True, "80", math.nan, -1, 101])
def test_coverage_with_a_bad_threshold_fails_closed(bad: object) -> None:
    # The schema refuses these; the evaluator must not trust that it was called through it.
    facts = _facts(coverage=100.0)
    (why,) = [f.reason for f in evaluate((_Raw("coverage_at_least", bad),), "g", facts)]
    assert "threshold" in why


class _Raw:
    """A definition-of-done entry that bypassed schema validation."""

    def __init__(self, check: str, value: object, stage: str = "g") -> None:
        self.check, self.value, self.stage = check, value, stage


# --- no_findings_above --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sev", "above", "ok"),
    [
        ("low", "low", True),
        ("medium", "medium", True),
        ("low", "medium", True),
        ("medium", "low", False),
        ("high", "medium", False),
        ("critical", "high", False),
        ("critical", "critical", True),
        ("high", "critical", True),
    ],
)
def test_no_findings_above_threshold_order(sev: str, above: str, ok: bool) -> None:
    f = _facts(findings=(Finding(sev, "t"),))
    assert (_reasons("no_findings_above", above, f) == []) is ok


def test_no_findings_above_lists_offenders_not_the_allowed() -> None:
    fs = (Finding("low", "nit"), Finding("high", "sql injection"), Finding("critical", "rce"))
    (why,) = _reasons("no_findings_above", "medium", _facts(findings=fs))
    assert "sql injection" in why
    assert "rce" in why
    assert "nit" not in why
    assert "2" in why


def test_no_findings_empty_is_clean_but_none_is_unreadable() -> None:
    assert _reasons("no_findings_above", "low", _facts(findings=())) == []
    (why,) = _reasons("no_findings_above", "low", _facts(findings=None))
    assert "findings" in why


def test_no_findings_unknown_severity_counts_as_above_any_threshold() -> None:
    f = _facts(findings=(Finding("sev9", "mystery"),))
    (why,) = _reasons("no_findings_above", "critical", f)
    assert "mystery" in why


@pytest.mark.parametrize("bad", [None, "urgent", 3])
def test_no_findings_bad_threshold_fails_closed(bad: object) -> None:
    (why,) = [f.reason for f in evaluate((_Raw("no_findings_above", bad),), "g", _facts())]
    assert "threshold" in why


# --- the registry, selection and failure handling -----------------------------------------


def test_only_the_named_stages_checks_run() -> None:
    items = (_dod("ac_present", stage="other"), _dod("checks_green", stage="g"))
    assert evaluate(items, "g", _facts(acceptance_criteria=None)) == ()
    assert evaluate(items, "other", _facts(acceptance_criteria=None))


def test_every_failure_is_reported_in_config_order() -> None:
    items = (_dod("ac_present"), _dod("coverage_at_least", 50), _dod("checks_green"))
    facts = _facts(acceptance_criteria=None, coverage=1.0, check_results=None)
    got = evaluate(items, "g", facts)
    assert [f.check for f in got] == ["ac_present", "coverage_at_least", "checks_green"]
    assert all(f.stage == "g" for f in got)


def test_unknown_check_name_fails_closed() -> None:
    (f,) = evaluate((_Raw("free_form_expr", None),), "g", _facts())
    assert "unknown" in f.reason
    assert "free_form_expr" in f.reason


def test_an_evaluator_that_raises_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(value: object, facts: DodFacts) -> str | None:
        raise RuntimeError("kaboom")

    monkeypatch.setitem(dod.CHECKS, "ac_present", boom)
    (f,) = evaluate((_dod("ac_present"),), "g", _facts())
    assert "could not be evaluated" in f.reason


def test_evaluators_are_pure_and_repeatable() -> None:
    items = (_dod("checks_green"), _dod("no_findings_above", "low"))
    facts = _facts(findings=(Finding("high", "x"),))
    assert evaluate(items, "g", facts) == evaluate(items, "g", facts)


def test_no_definition_of_done_means_nothing_to_check() -> None:
    assert evaluate((), "g", _facts()) == ()
    assert refusal((), "g", _facts()) is None


# --- refusal: what a gate or stage exit asks ----------------------------------------------


def test_refusal_is_a_registered_blocked_reason() -> None:
    assert BLOCKED_REASONS.get(dod.BLOCKED_REASON) is not None
    assert dod.BLOCKED_REASON == "definition_of_done_failed"


def test_refusal_none_when_all_pass() -> None:
    items = (_dod("ac_present"), _dod("checks_green"), _dod("coverage_at_least", 80))
    assert refusal(items, "g", _facts()) is None


def test_refusal_explains_what_is_missing() -> None:
    items = (_dod("ac_present"), _dod("coverage_at_least", 95))
    r = refusal(items, "g", _facts(coverage=50.0))
    assert r is not None
    assert r.reason == dod.BLOCKED_REASON
    assert "coverage" in r.detail
    assert "50" in r.detail
    assert "95" in r.detail
    assert "ac_present" not in r.detail  # the passing check is not a complaint
    assert len(r.failures) == 1


def test_refusal_with_missing_facts_object_fails_closed() -> None:
    r = refusal((_dod("ac_present"),), "g", None)
    assert r is not None
    assert r.failures


def test_refusal_with_no_facts_but_no_checks_passes() -> None:
    # nothing configured for this stage: nothing to be missing
    assert refusal((), "g", None) is None


# --- strictness found by the mutation pass --------------------------------------------------


@pytest.mark.parametrize("kw", [{"check_sha": None}, {"head_sha": None}])
def test_checks_green_a_missing_sha_says_so_not_a_crash(kw: dict[str, object]) -> None:
    (why,) = _reasons("checks_green", None, _facts(**kw))
    assert why == "the check results cannot be tied to the head commit"


def test_checks_green_stale_message_is_exact() -> None:
    (why,) = _reasons("checks_green", None, _facts(check_sha=OTHER))
    assert why == f"the check results are stale: they are for {OTHER}, the head is {SHA}"


def test_checks_green_a_name_reported_twice_is_flagged_even_if_both_pass() -> None:
    res = (CheckStatus("a", "passed"), CheckStatus("a", "neutral"))
    (why,) = _reasons("checks_green", None, _facts(check_results=res))
    assert "a (reported twice)" in why


def test_no_evidence_is_named_as_such() -> None:
    (f,) = evaluate((_dod("ac_present"),), "g", None)
    assert f.reason == "no evidence was supplied"


def test_registering_a_check_name_twice_is_refused() -> None:
    with pytest.raises(ValueError, match="already registered"):
        dod.check("ac_present")(lambda v, f: None)


# --- review pass 1 ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", " ", "   \n", "abc", "A" * 40, "g" * 40, "a" * 39, "a" * 41])
@pytest.mark.parametrize("which", ["head_sha", "check_sha"])
def test_checks_green_refuses_a_sha_that_is_not_40_hex(which: str, bad: str) -> None:
    # Equal blank SHAs must not count as "the same commit".
    kw: dict[str, object] = {"head_sha": bad, "check_sha": bad}
    kw[which] = bad
    (why,) = _reasons("checks_green", None, _facts(**kw))
    assert why == "the check results cannot be tied to the head commit"


def test_checks_green_one_valid_one_blank_sha_is_not_tied() -> None:
    (why,) = _reasons("checks_green", None, _facts(check_sha=""))
    assert why == "the check results cannot be tied to the head commit"


def test_required_checks_unreadable_is_not_done() -> None:
    (why,) = _reasons("checks_green", None, _facts(required_checks=None))
    assert why == "the list of required checks could not be read"


def test_required_checks_default_is_unreadable() -> None:
    facts = DodFacts(head_sha=SHA, check_sha=SHA, check_results=(CheckStatus("a", "passed"),))
    assert _reasons("checks_green", None, facts)


def test_required_checks_empty_means_none_required() -> None:
    assert _reasons("checks_green", None, _facts(required_checks=())) == []


@pytest.mark.parametrize(
    "make", [lambda: iter(()), lambda: (r for r in tuple[CheckStatus, ...]()), lambda: iter([])]
)
def test_an_empty_iterator_of_results_is_not_done(make: object) -> None:
    (why,) = _reasons("checks_green", None, _facts(check_results=make()))  # type: ignore[operator]
    assert why == "no check results are available"


def test_a_generator_of_results_is_read_once_and_judged() -> None:
    gen = (CheckStatus(n, s) for n, s in [("a", "passed"), ("b", "failed")])
    (why,) = _reasons("checks_green", None, _facts(check_results=gen))
    assert "b (failed)" in why


def test_two_non_passing_statuses_of_one_name_are_listed_sorted() -> None:
    res = (CheckStatus("a", "pending"), CheckStatus("a", "failed"))
    (why,) = _reasons("checks_green", None, _facts(check_results=res))
    assert why == "not green: a (failed, pending)"


def test_status_vocabulary_is_the_one_waits_uses() -> None:
    from sto.engine.handlers import waits

    assert dod._PASSING is waits._PASSING  # type: ignore[attr-defined]


def test_coverage_message_does_not_round() -> None:
    (why,) = _reasons("coverage_at_least", 80, _facts(coverage=79.9999999))
    assert "79.9999999" in why
    assert "is 80%" not in why


class _Booby:
    """An entry whose attributes cannot be read."""

    @property
    def stage(self) -> str:
        raise RuntimeError("boom")

    check = "ac_present"
    value = None


def test_an_entry_that_cannot_be_read_fails_closed_not_raises() -> None:
    (f,) = evaluate((_Booby(),), "g", _facts())
    assert f.reason == "the check could not be evaluated"
