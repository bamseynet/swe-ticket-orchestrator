"""The shared adapter conformance suite (D4-01). Import it as ``contract.suite``.

This package is also a pytest plugin, loaded for every session by ``-p contract`` in ``addopts``.
It must import nothing from ``sto``: a plugin that imports ``sto`` before pytest-cov starts makes
coverage skip the whole package. So the hooks only FORWARD to ``contract.suite`` when a test module
has already imported it (no conformance subclass can exist without that import), and do nothing
otherwise.
"""

from __future__ import annotations

import sys
from collections.abc import Generator
from typing import Any

import pytest

pytest.register_assert_rewrite("contract.suite")  # before it is imported, for readable failures


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    session: pytest.Session, config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Runs before ``-m`` and ``-k`` deselect, so the CI selector cannot hide an orphan."""
    suite = sys.modules.get("contract.suite")
    if suite is not None:
        suite.guard_collection(config, items)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[Any]
) -> Generator[None, Any, None]:
    outcome = yield
    suite = sys.modules.get("contract.suite")
    if suite is not None:
        suite.enforce_outcome(item, outcome.get_result())
