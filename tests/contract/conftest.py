"""Guards for the conformance suite (D4-01). Outside this directory, load them with
``pytest_plugins = ["contract.conftest"]`` in that directory's ``conftest.py``.

* A conformance subclass that collected no test, or lost one, fails the run. The check sees the
  items before ``-m`` and ``-k`` deselect (``tryfirst``), so the CI selector ``-m contract`` cannot
  hide an orphan.
* A suite test that is skipped or xfailed fails, unless ``pending_controls`` made it xfail.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest

pytest.register_assert_rewrite("contract.suite")  # before it is imported, for readable failures
from contract.suite import check_collection, enforce_outcome  # noqa: E402


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    session: pytest.Session, config: pytest.Config, items: list[pytest.Item]
) -> None:
    problems = check_collection(items, config.args)
    if problems:
        raise pytest.UsageError("conformance suite: " + "; ".join(problems))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[Any]
) -> Generator[None, Any, None]:
    outcome = yield
    enforce_outcome(item, outcome.get_result())
