"""Placeholder for the e2e job (D0-09): the whole local stack is up and answering.

Selected by the ``e2e`` marker (``pytest -m e2e``); a test under ``tests/e2e/`` is in that tier
without a marker (D0-09a). D1-10 adds the walking-skeleton journey here.
"""

from __future__ import annotations

from _dynamodb import list_tables


def test_stack_is_up_and_dynamodb_answers() -> None:
    assert isinstance(list_tables()["TableNames"], list)
