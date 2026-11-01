"""Error classes. Every ``StoError`` is exactly one of ``transient``, ``permanent``, ``degraded``
(PLAN 6.2 failure rules)."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar


class FailureClass(StrEnum):
    TRANSIENT = "transient"  # retried with backoff, up to the stage's max_attempts
    PERMANENT = "permanent"  # BLOCKED at once; only a person's audited Retry re-runs it
    DEGRADED = "degraded"  # gate opens flagged, or the run blocks if fail_closed


class StoError(Exception):
    """Base class. Concrete subclasses must set ``failure_class``; the base cannot be raised."""

    failure_class: ClassVar[FailureClass]

    def __init__(self, *args: object) -> None:
        if not hasattr(type(self), "failure_class"):
            raise TypeError(f"{type(self).__name__} must declare a failure_class")
        super().__init__(*args)

    @property
    def retryable(self) -> bool:
        return self.failure_class is FailureClass.TRANSIENT


class TransientError(StoError):
    failure_class = FailureClass.TRANSIENT


class PermanentError(StoError):
    failure_class = FailureClass.PERMANENT


class DegradedError(StoError):
    failure_class = FailureClass.DEGRADED


class InvalidIdError(PermanentError):
    pass


class InvalidTransitionError(PermanentError):
    pass
