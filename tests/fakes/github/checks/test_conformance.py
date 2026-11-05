"""D4-20: the conformance suite's SCM section, run UNMODIFIED against the checks fake.

``FakeGitHubChecks`` extends D4-19's ``FakeGitHubPulls``, so D4-19's target (the suite's three
stand-in ops turned into the real GitHub requests, nothing more) is reused as it is and only the
server it builds is swapped. Passing proves the checks, rulesets and dispatch extension left the
PR comment, paging, fault, rate-limit and auth behaviour the suite targets as it was.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import ClassVar
from unittest import mock

import pytest

from contract.suite import AdapterConformance, Port, Target
from fakes.github.checks import FakeGitHubChecks
from fakes.github.pulls import test_conformance as pulls_conformance

pytestmark = pytest.mark.contract


def fake_github_checks() -> Target:
    with mock.patch.object(pulls_conformance, "FakeGitHubPulls", FakeGitHubChecks):
        target = pulls_conformance.FakeGitHubPullsTarget()
    assert isinstance(target.server, FakeGitHubChecks)
    return target


class TestFakeGitHubChecks(AdapterConformance):
    """All eight sections of the SCM port's suite, against the checks fake."""

    port = Port.SCM
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": fake_github_checks}
