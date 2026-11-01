"""Stands in for another module (e.g. engine) registering its own event, command and reason."""

from __future__ import annotations

from dataclasses import dataclass

# NOTE: the test.* names below are permanent on the shared registries for the whole pytest
# process, so no test may assert the exact contents of EVENTS.names() and friends.
from sto.domain import BLOCKED_REASONS, COMMANDS, EVENTS


@EVENTS.register("test.external_event")
@dataclass(frozen=True)
class ExternalEvent:
    pass


@COMMANDS.register("test.external_command")
class ExternalCommand:
    pass


@BLOCKED_REASONS.register("test_external_reason")
class ExternalReason:
    pass
