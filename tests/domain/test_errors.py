from __future__ import annotations

import pytest

from sto.domain import (
    DegradedError,
    FailureClass,
    PermanentError,
    StoError,
    TransientError,
)


def test_failure_classes() -> None:
    assert {c.value for c in FailureClass} == {"transient", "permanent", "degraded"}
    assert TransientError("x").failure_class is FailureClass.TRANSIENT
    assert PermanentError("x").failure_class is FailureClass.PERMANENT
    assert DegradedError("x").failure_class is FailureClass.DEGRADED
    assert issubclass(TransientError, StoError)


def test_stoerror_cannot_be_unclassified() -> None:
    with pytest.raises(TypeError):
        StoError("x")

    class Sub(StoError):
        pass

    with pytest.raises(TypeError):
        Sub("x")


def test_only_transient_is_retryable() -> None:
    assert TransientError("x").retryable
    assert not PermanentError("x").retryable
    assert not DegradedError("x").retryable
