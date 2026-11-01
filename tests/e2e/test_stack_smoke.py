"""Placeholder for the e2e job (D0-09): the whole local stack is up and answering.

Selected by path (``pytest -m integration tests/e2e``). It carries the ``integration`` marker
because there is no ``e2e`` tier marker yet (D0-09a). D1-10 adds the walking-skeleton journey here.
"""

from __future__ import annotations

import pytest

from _dynamodb import list_tables


@pytest.mark.integration
def test_stack_is_up_and_dynamodb_answers() -> None:
    assert isinstance(list_tables()["TableNames"], list)
