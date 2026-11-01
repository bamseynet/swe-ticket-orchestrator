"""Shared plumbing for the fakes: receipts, the idempotency ledger and spy recording."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

from sto.adapters.fake.spy import SpyCall, SpyWriter
from sto.adapters.ports import (
    ChangeKind,
    ExternalChange,
    IdempotencyKeyReuseError,
    MalformedWebhookError,
    PrRef,
    RawWebhook,
    RepoRef,
    StaleHeadError,
    TicketRef,
)
from sto.domain.errors import TransientError
from sto.domain.models import Receipt


class FakeBase:
    """Results are labelled ``simulated`` (PLAN 6.3); each fake has its own idempotency ledger."""

    def __init__(self, port: str, spy: SpyWriter | None) -> None:
        self.spy = spy or SpyWriter()
        self.read_back_verified = True  # False models "accepted but not applied" (ADR-0011)
        self._port, self._seq = port, 0
        self._noop = False
        self._unapplied = False
        self._failures: dict[str, list[str]] = {}
        self._ledger: dict[tuple[str, str], tuple[dict[str, Any], Any]] = {}

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq}"

    def _receipt(self, prefix: str, url: str = "", external_id: str | None = None) -> Receipt:
        return Receipt(
            external_id or self._next_id(prefix),
            url,
            read_back_verified=self.read_back_verified,
            simulated=True,
        )

    # State a rollback must not undo: the spy, the ledger, flags, injected failures and ID counter.
    _KEEP: tuple[str, ...] = ("spy", "_ledger", "_noop", "_unapplied", "_failures", "_seq")

    _WRITES: frozenset[str] = frozenset()  # each fake names its write methods

    def _inject(self, method: str, mode: str, times: int) -> None:
        if method not in self._WRITES:
            raise ValueError(f"no write method {method!r}; one of {sorted(self._WRITES)}")
        self._failures.setdefault(method, []).extend([mode] * times)

    def fail_next(self, method: str, times: int = 1) -> None:
        """Make the next ``times`` calls to ``method`` raise a transient error and apply nothing
        (the RETRYING path)."""
        self._inject(method, "fail", times)

    def lose_response_next(self, method: str, times: int = 1) -> None:
        """Make the next ``times`` calls to ``method`` apply, then raise a transient error: the
        write happened and the caller never saw the answer."""
        self._inject(method, "lose", times)

    def stale_next(self, method: str, times: int = 1) -> None:
        """Make the next ``times`` calls to ``method`` raise ``StaleHeadError``, applying none."""
        self._inject(method, "stale", times)

    def _apply[T](self, apply: Callable[[], T]) -> T:
        """Run ``apply``; with ``read_back_verified`` off its effects are rolled back."""
        if self.read_back_verified:
            return apply()
        saved = {k: copy.deepcopy(v) for k, v in self.__dict__.items() if k not in self._KEEP}
        result = apply()
        self.__dict__.update(saved)
        self._noop = self._unapplied = True
        return result

    def _write[T](
        self, method: str, args: dict[str, Any], key: str | None, apply: Callable[[], T]
    ) -> T:
        """Apply once per ``(method, key)``; a replay returns the first result, other arguments
        are refused. Every attempt, refused or not, reaches the spy. ``apply`` sets ``_noop`` when
        it accepted the call but changed nothing."""
        replayed, lost, self._noop, self._unapplied = False, False, False, False
        ledger_key = (method, key or "")
        injected = (self._failures.get(method) or [""]).pop(0)
        try:
            if injected == "fail":
                raise TransientError(f"injected failure in {method}")
            if injected == "stale":
                raise StaleHeadError(f"injected stale head in {method}")
            if key is not None and ledger_key in self._ledger:
                first_args, result = self._ledger[ledger_key]
                if first_args != args:
                    raise IdempotencyKeyReuseError(
                        f"key {key!r} was used for {first_args}, now {args}"
                    )
                replayed = True
            else:
                result = self._apply(apply)
                if key is not None and not self._unapplied:  # a retry must really write
                    self._ledger[ledger_key] = (args, result)
            if injected == "lose":
                lost = True
                raise TransientError(f"response of {method} lost")
        except Exception as exc:
            name = type(exc).__name__
            self.spy.record(
                SpyCall(self._port, method, args, key, error=name, lost=lost, noop=self._noop)
            )
            raise
        self.spy.record(SpyCall(self._port, method, args, key, replayed=replayed, noop=self._noop))
        return result  # type: ignore[no-any-return]


# --- webhook bodies: ``{"changes": [{"kind": ..., ...}]}`` ---------------------------------


def load_json(raw: RawWebhook) -> Any:
    try:
        return json.loads(raw.body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MalformedWebhookError("body is not JSON") from exc


def _text(item: dict[str, Any], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _repo(item: dict[str, Any]) -> RepoRef:
    parts = _text(item, "repo").split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("repo must be owner/name")
    return RepoRef(*parts)


def _change(item: dict[str, Any]) -> ExternalChange:
    """One change, with the fields its kind needs (a nudge with no target is useless)."""
    kind = ChangeKind(item["kind"])
    if kind is ChangeKind.TICKET:
        return ExternalChange(kind, ticket=TicketRef("fake", _text(item, "ticket")))
    repo = _repo(item)
    number = item.get("pr")
    if kind in (ChangeKind.PR, ChangeKind.REVIEW):
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise ValueError("pr must be a positive integer")
        return ExternalChange(kind, repo=repo, pr=PrRef(repo, number))
    if kind is ChangeKind.PUSH:
        return ExternalChange(kind, repo=repo, branch=_text(item, "branch"), sha=_text(item, "sha"))
    if kind is ChangeKind.CHECK:
        return ExternalChange(kind, repo=repo, sha=_text(item, "sha"), check=_text(item, "check"))
    if kind is ChangeKind.MERGE_GROUP:
        return ExternalChange(kind, repo=repo, sha=_text(item, "sha"), branch=_text(item, "branch"))
    return ExternalChange(kind, repo=repo)  # installation


def parse_changes(raw: RawWebhook, allowed: frozenset[ChangeKind]) -> list[ExternalChange]:
    """An empty body is no change; anything unreadable, or of a kind this port does not receive,
    is refused cleanly."""
    if not raw.body:
        return []
    body = load_json(raw)
    changes = body.get("changes") if isinstance(body, dict) else None
    if not isinstance(changes, list):
        raise MalformedWebhookError("expected an object with a 'changes' list")
    out: list[ExternalChange] = []
    for item in changes:
        try:
            change = _change(item)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise MalformedWebhookError(f"unreadable change {item!r}") from exc
        if change.kind not in allowed:
            raise MalformedWebhookError(f"{change.kind} is not delivered to this port")
        out.append(change)
    return out
