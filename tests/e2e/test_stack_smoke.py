"""Smoke test for the e2e job (D0-09): the local stack's DynamoDB Local is up and answering.

The job selects by the ``e2e`` marker (anything under ``tests/e2e/`` is in that tier). This test
also carries ``integration``. The walking-skeleton journey is ``test_skeleton.py`` (D1-10).
"""

from __future__ import annotations

import pytest

from _dynamodb import list_tables


@pytest.mark.integration
def test_stack_is_up_and_dynamodb_answers() -> None:
    assert isinstance(list_tables()["TableNames"], list)
