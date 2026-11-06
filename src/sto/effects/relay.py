"""Outbox relay (D3-11): deliver committed gate signals to the driver, until delivered.

The gate service commits a decision and its outbox entry (``RUN#r / OUT#<ulid>``) in one
transaction (PLAN 4.3 rule 6, 4.8). This relay reads those entries and hands each to a
:class:`SignalSink` (Step Functions ``SendTaskSuccess`` in AWS, the local driver's inbox locally).

* **Everything goes through the store port.** The only write is a conditional ``Delete`` at the
  entry's version once the sink has confirmed, so memory, SQLite and DynamoDB agree and two relays
  racing cannot both delete a newer entry.
* **At-least-once, never dropped.** An entry leaves the store only after the sink returned (or,
  for "already closed", after a reconcile confirmed the run has the decision). A crash anywhere
  leaves the entry, and the next sweep delivers it again. The sink receives the entry's key as its
  idempotency key and must apply a repeat once (the reducer refuses a late duplicate).
* **Ordering per run.** A run's entries are delivered in key order and a failure stops that run's
  queue at the failing entry, so a later entry never overtakes an earlier one. Other runs go on.
* **A task token that is not stored yet** (the decision won the race with the step that stores
  it) is :class:`TokenNotStoredError`: the entry waits, and the step that stores the token calls
  :meth:`OutboxRelay.drain` for its run, which signals at once (PLAN 4.8).
* **"Already closed"** (``TaskTimedOut``, a finished execution) is :class:`AlreadyClosedError`.
  It counts as delivered only if ``SignalSink.reconcile`` finds the decision already applied;
  otherwise the run closed without hearing it, the entry stays, and it raises the alarm.
* **Alarm.** Each sweep publishes ``outbox_stuck`` (entries older than ``stuck_after`` seconds)
  and ``outbox_oldest_age_seconds`` (0 when empty) to the :class:`Metrics` port. The age is the
  entry's ULID time against the injected clock; no wall clock is read here.

Per-run order follows the ULID, which orders by millisecond only; entries of one run in the same
millisecond are not ordered among themselves (the gate service's chain head serialises a run's
decisions, so they are committed one after another, but their ULIDs are random within a ms).
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from sto.domain import OutboxId, PermanentError, RunId, TransientError
from sto.store.ports import ConditionFailedError, Item, Key, Scope, Store, VersionIs

log = logging.getLogger(__name__)

OUTBOX_PREFIX = "OUT#"
DEFAULT_STUCK_AFTER_SECONDS = 300.0
_PAGE = 100


class TokenNotStoredError(TransientError):
    """The run has no task token yet. The entry waits for the step that stores it."""


class AlreadyClosedError(PermanentError):
    """The run takes no more signals (timed out, finished). Reconcile before calling it done."""


@dataclass(frozen=True)
class OutboxEntry:
    run_id: RunId
    id: OutboxId
    key: Key
    version: int
    data: dict[str, Any]

    @property
    def idempotency_key(self) -> str:
        return f"{self.key.pk}/{self.key.sk}"

    @property
    def created_ms(self) -> int:
        return self.id.value >> 80


class SignalSink(Protocol):
    def deliver(self, entry: OutboxEntry) -> None:
        """Signal the run. Raise ``TokenNotStoredError`` or any ``TransientError`` to be retried,
        ``AlreadyClosedError`` if the run no longer takes signals. A repeat of one entry
        (same ``idempotency_key``) must take effect once."""
        ...

    def reconcile(self, entry: OutboxEntry) -> bool:
        """After ``AlreadyClosedError``: True if the run already reflects this entry."""
        ...


class Metrics(Protocol):
    def gauge(self, name: str, value: float) -> None: ...


@dataclass(frozen=True)
class RelayReport:
    delivered: int = 0
    waiting: int = 0  # no task token yet
    failed: int = 0  # a delivery that did not work; the entry stays
    stuck: int = 0
    oldest_age_seconds: float = 0.0

    def __add__(self, other: RelayReport) -> RelayReport:
        return RelayReport(
            self.delivered + other.delivered,
            self.waiting + other.waiting,
            self.failed + other.failed,
            self.stuck + other.stuck,
            max(self.oldest_age_seconds, other.oldest_age_seconds),
        )


class OutboxRelay:
    def __init__(
        self,
        store: Store,
        scope: Scope,
        sink: SignalSink,
        *,
        metrics: Metrics,
        clock: Callable[[], float],
        stuck_after: float = DEFAULT_STUCK_AFTER_SECONDS,
    ) -> None:
        self._store, self._scope, self._sink = store, scope, sink
        self._metrics, self._clock, self._stuck_after = metrics, clock, stuck_after

    def pending(self, run_id: RunId) -> list[OutboxEntry]:
        """The run's undelivered entries, oldest first."""
        out: list[OutboxEntry] = []
        cursor: str | None = None
        while True:
            page = self._store.query(
                self._scope, f"RUN#{run_id}", sk_prefix=OUTBOX_PREFIX, limit=_PAGE, cursor=cursor
            )
            out += [_entry(run_id, i) for i in page.items]
            cursor = page.cursor
            if cursor is None:
                return out

    def drain(self, run_id: RunId) -> RelayReport:
        """Deliver this run's entries in order, stopping at the first that does not go."""
        return self._drain(run_id)

    def sweep(self, run_ids: Iterable[RunId]) -> RelayReport:
        """Drain every run, then publish the alarm metrics. One run's failure never hides
        another's."""
        total = RelayReport()
        for run_id in run_ids:
            total += self._drain(run_id)
        self._metrics.gauge("outbox_stuck", total.stuck)
        self._metrics.gauge("outbox_oldest_age_seconds", total.oldest_age_seconds)
        return total

    def _drain(self, run_id: RunId) -> RelayReport:
        delivered = waiting = failed = 0
        left: list[OutboxEntry] = []
        queue = self.pending(run_id)
        for n, entry in enumerate(queue):
            try:
                self._sink.deliver(entry)
            except TokenNotStoredError:
                waiting += 1
                left = queue[n:]
                break
            except AlreadyClosedError:
                if not self._reconciled(entry):
                    failed += 1
                    left = queue[n:]
                    break
            except Exception as e:  # kept, retried by the next sweep, alarmed when it ages
                log.error("delivering %s failed: %r", entry.idempotency_key, e)
                failed += 1
                left = queue[n:]
                break
            self._remove(entry)
            delivered += 1
        return RelayReport(delivered, waiting, failed, *self._ages(left))

    def _reconciled(self, entry: OutboxEntry) -> bool:
        try:
            return self._sink.reconcile(entry)
        except Exception as e:
            log.error("reconciling %s failed: %r", entry.idempotency_key, e)
            return False

    def _remove(self, entry: OutboxEntry) -> None:
        # a failed condition means another relay delivered and removed it first
        with contextlib.suppress(ConditionFailedError):
            self._store.delete(self._scope, entry.key, when=VersionIs(entry.version))

    def _ages(self, left: list[OutboxEntry]) -> tuple[int, float]:
        now_ms = self._clock() * 1000
        ages = [max(0.0, (now_ms - e.created_ms) / 1000) for e in left]
        return sum(a >= self._stuck_after for a in ages), max(ages, default=0.0)


def _entry(run_id: RunId, item: Item) -> OutboxEntry:
    return OutboxEntry(
        run_id,
        OutboxId.parse(item.key.sk[len(OUTBOX_PREFIX) :]),
        item.key,
        item.version,
        item.data,
    )


__all__ = [
    "AlreadyClosedError",
    "Metrics",
    "OutboxEntry",
    "OutboxRelay",
    "RelayReport",
    "SignalSink",
    "TokenNotStoredError",
]
