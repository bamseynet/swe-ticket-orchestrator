"""Shared plumbing for the fakes: receipts, the idempotency ledger and spy recording."""

from __future__ import annotations

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
from sto.domain.errors import StoError
from sto.domain.models import Receipt


class FakeBase:
    """Results are labelled ``simulated`` (PLAN 6.3); each fake has its own idempotency ledger."""

    def __init__(self, port: str, spy: SpyWriter | None) -> None:
        self.spy = spy or SpyWriter()
        self.read_back_verified = True  # set False to model "accepted but not applied"
        self._port, self._seq = port, 0
        self._ledger: dict[str, tuple[dict[str, Any], Any]] = {}

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

    def _write[T](
        self, method: str, args: dict[str, Any], key: str | None, apply: Callable[[], T]
    ) -> T:
        """Apply once per key; a replay returns the first result, other arguments are refused.
        Every attempt, refused or not, reaches the spy."""
        replayed = False
        try:
            if key is not None and key in self._ledger:
                first_args, result = self._ledger[key]
                if first_args != args:
                    raise IdempotencyKeyReuseError(
                        f"key {key!r} was used for {first_args}, now {args}"
                    )
                replayed = True
            else:
                result = apply()
                if key is not None:
                    self._ledger[key] = (args, result)
        except StoError as exc:
            self.spy.record(SpyCall(self._port, method, args, key, error=type(exc).__name__))
            raise
        self.spy.record(SpyCall(self._port, method, args, key, replayed=replayed))
        return result  # type: ignore[no-any-return]


# --- webhook bodies: ``{"changes": [{"kind": ..., ...}]}`` ---------------------------------


def load_json(raw: RawWebhook) -> Any:
    try:
        return json.loads(raw.body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MalformedWebhookError("body is not JSON") from exc


def parse_changes(raw: RawWebhook) -> list[ExternalChange]:
    """An empty body is no change; anything unreadable is refused cleanly."""
    if not raw.body:
        return []
    body = load_json(raw)
    changes = body.get("changes") if isinstance(body, dict) else None
    if not isinstance(changes, list):
        raise MalformedWebhookError("expected an object with a 'changes' list")
    out: list[ExternalChange] = []
    for item in changes:
        try:
            kind = ChangeKind(item["kind"])
            repo = RepoRef(*item["repo"].split("/")) if "repo" in item else None
            out.append(
                ExternalChange(
                    kind,
                    ticket=TicketRef("fake", str(item["ticket"])) if "ticket" in item else None,
                    repo=repo,
                    pr=PrRef(repo, int(item["pr"])) if repo and "pr" in item else None,
                    sha=item.get("sha"),
                    branch=item.get("branch"),
                    check=item.get("check"),
                )
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise MalformedWebhookError(f"unreadable change {item!r}") from exc
    return out
