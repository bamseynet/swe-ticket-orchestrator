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
    TicketRef,
)
from sto.domain.models import Receipt


class FakeBase:
    """Results are labelled ``simulated`` (PLAN 6.3); each fake has its own idempotency ledger."""

    def __init__(self, port: str, spy: SpyWriter | None) -> None:
        self.spy = spy or SpyWriter()
        self.read_back_verified = True  # False models "accepted but not applied" (ADR-0011)
        self._port, self._seq = port, 0
        self._noop = False
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

    def _apply[T](self, apply: Callable[[], T]) -> T:
        """Run ``apply``; with ``read_back_verified`` off its effects are rolled back."""
        if self.read_back_verified:
            return apply()
        keep = ("spy", "_ledger", "_noop")
        saved = {k: copy.deepcopy(v) for k, v in self.__dict__.items() if k not in keep}
        result = apply()
        self.__dict__.update(saved)
        self._noop = True
        return result

    def _write[T](
        self, method: str, args: dict[str, Any], key: str | None, apply: Callable[[], T]
    ) -> T:
        """Apply once per ``(method, key)``; a replay returns the first result, other arguments
        are refused. Every attempt, refused or not, reaches the spy. ``apply`` sets ``_noop`` when
        it accepted the call but changed nothing."""
        replayed, self._noop = False, False
        ledger_key = (method, key or "")
        try:
            if key is not None and ledger_key in self._ledger:
                first_args, result = self._ledger[ledger_key]
                if first_args != args:
                    raise IdempotencyKeyReuseError(
                        f"key {key!r} was used for {first_args}, now {args}"
                    )
                replayed = True
            else:
                result = self._apply(apply)
                if key is not None:
                    self._ledger[ledger_key] = (args, result)
        except Exception as exc:
            self.spy.record(SpyCall(self._port, method, args, key, error=type(exc).__name__))
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
