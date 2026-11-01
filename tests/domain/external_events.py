"""Stands in for another module (e.g. engine) registering its own event, command and reason."""

from __future__ import annotations

from dataclasses import dataclass

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
