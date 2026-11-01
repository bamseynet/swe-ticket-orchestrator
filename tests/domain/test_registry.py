from __future__ import annotations

import external_events
import pytest

from sto.domain import BLOCKED_REASONS, COMMANDS, EVENTS, Registry


def test_other_module_registers_on_shared_registries_without_editing_domain() -> None:
    assert EVENTS.get("test.external_event") is external_events.ExternalEvent
    assert COMMANDS.get("test.external_command") is external_events.ExternalCommand
    assert BLOCKED_REASONS.get("test_external_reason") is external_events.ExternalReason
    assert not external_events.ExternalEvent.__module__.startswith("sto.")
    assert EVENTS.name_of(external_events.ExternalEvent) == "test.external_event"


def test_duplicates_unknown_and_blank() -> None:
    reg: Registry[object] = Registry("blocked_reason")
    reg.register("loop_exhausted")(int)
    with pytest.raises(ValueError, match="already registered"):
        reg.register("loop_exhausted")(str)
    with pytest.raises(KeyError, match="blocked_reason"):
        reg.get("nope")
    with pytest.raises(ValueError, match="non-empty"):
        reg.register("")(int)


def test_same_class_same_name_is_idempotent() -> None:
    reg: Registry[object] = Registry("command")
    reg.register("x")(int)
    reg.register("x")(int)
    assert reg.names() == ("x",)


def test_one_class_cannot_have_two_names() -> None:
    reg: Registry[object] = Registry("event")
    reg.register("a")(int)
    with pytest.raises(ValueError, match="already registered as 'a'"):
        reg.register("b")(int)
    assert reg.names() == ("a",)
    assert reg.name_of(int) == "a"
    with pytest.raises(KeyError):
        reg.name_of(str)
