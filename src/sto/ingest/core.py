"""Generic webhook ingest (D4-03, ADR-0009): verify, dedupe, enqueue, answer inside the deadline.

A webhook is a nudge, not a fact. The body is verified on the RAW bytes, a delivery is processed
at most once per ``HOOK#surface#id`` record, and the queued ``Nudge`` always tells its consumer to
re-read current state. Vendor-specific code (D4-04 GitHub, Jira, Slack) supplies only a
``WebhookVerifier``; it never touches the store or the queue.

Answers: ``202`` queued, ``200`` duplicate (dropped, so the vendor stops retrying), ``401`` bad
signature or malformed headers (counted), ``503`` the store or queue failed, so the vendor retries.

* **Replay bound.** The delivery ID is not part of every vendor's signature, so an attacker who
  replays a genuine, signed delivery under another ID is not stopped by the ID, and one who
  re-sends a captured one is stopped only by the dedupe record. So a decision-shaped delivery
  (an approval, a merge) is never acted on from its body: the consumer re-reads the vendor's
  current state (``Nudge.reread`` cannot be turned off). A vendor with no signed timestamp has no
  other replay bound, so its ``SEEN`` record never expires. Only a vendor whose signature covers
  a timestamp gets a ``ttl`` on the record, set past twice the replay window, since an old replay
  is refused by the verifier anyway (PLAN 11, Delivery row).
* **Claim first, then enqueue.** The record is written before the enqueue so two simultaneous
  copies cannot both enqueue. If the enqueue fails the record is deleted again; otherwise the
  vendor's retry would be dropped as a duplicate and the nudge lost. If even that delete fails
  the 503 still goes out and ``webhook.release_failed`` is counted; the reconciler sweeps open
  runs, so a lost nudge is late, not missing.
* **A rejected delivery claims nothing**, so guessing a delivery ID cannot block the real one.
* **Deadline.** The work is one verify, one conditional write and one enqueue; the store and queue
  adapters carry the timeouts, so a hung dependency becomes a 503 inside the vendor's deadline
  (GitHub: 10 seconds, ADR-0016) rather than a vendor-side timeout.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sto.domain.errors import PermanentError, TransientError
from sto.store.ports import PLATFORM, Absent, ConditionFailedError, Key, Store

log = logging.getLogger(__name__)

ACCEPTED = 202
DUPLICATE = 200
UNAUTHORIZED = 401
UNAVAILABLE = 503

SEEN_SK = "SEEN"


class InvalidSignatureError(PermanentError):
    """The delivery is not genuine: wrong, missing or truncated signature, stale timestamp."""


# --- ports ------------------------------------------------------------------------------------


@runtime_checkable
class WebhookVerifier(Protocol):
    """A vendor's check that a delivery is genuine. Owned by ingest (ADR-0009).

    ``verify`` gets header names in lower case (``normalise_headers``) and the raw, unparsed body,
    and returns the vendor's delivery ID. It must compare the signature in constant time and raise
    ``PermanentError`` (``InvalidSignatureError``) for anything not genuine. It never parses the
    body for meaning. A delivery ID that is not covered by the signature stops nobody, so ingest
    treats the ID as a dedupe key only, and consumers re-read state.

    ``signed_timestamp`` is True only if the signature covers a timestamp the verifier checks
    against ``DedupePolicy.replay_window``; it decides whether the dedupe record may expire.
    """

    signed_timestamp: bool

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str: ...


@dataclass(frozen=True)
class Nudge:
    """What is queued: that something changed. Never the truth. ``reread`` is always True."""

    surface: str
    delivery_id: str
    body: bytes
    headers: Mapping[str, str]
    received_at: float
    reread: bool = True

    def __post_init__(self) -> None:
        if self.reread is not True:
            raise ValueError("a webhook delivery is a nudge: consumers must re-read state")


class NudgeQueue(Protocol):
    def enqueue(self, nudge: Nudge) -> None:
        """Raise on any failure; ingest then answers 503 so the vendor retries."""
        ...


class Metrics(Protocol):
    def incr(self, name: str, **tags: str) -> None: ...


@dataclass(frozen=True)
class DedupePolicy:
    """``replay_window`` (seconds) is set only for a vendor with a signed timestamp."""

    replay_window: float | None = None

    def __post_init__(self) -> None:
        if self.replay_window is not None and not self.replay_window > 0:
            raise ValueError("replay_window must be positive")


@dataclass(frozen=True)
class IngestResponse:
    status: int
    body: str = field(default="")


# --- headers ----------------------------------------------------------------------------------


def normalise_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Lower-case the names and strip the values. Two names that differ only in case must agree,
    else which one a verifier sees would depend on dict order: that is refused."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        key, val = name.strip().lower(), value.strip()
        if key in out and out[key] != val:
            raise PermanentError(f"conflicting values for header {key!r}")
        out[key] = val
    return out


# --- ingest -----------------------------------------------------------------------------------


class WebhookIngest:
    def __init__(
        self,
        surface: str,
        verifier: WebhookVerifier,
        store: Store,
        queue: NudgeQueue,
        metrics: Metrics,
        *,
        clock: Callable[[], float] = time.time,
        dedupe: DedupePolicy | None = None,
    ) -> None:
        if not surface or surface != surface.strip() or "#" in surface:
            raise ValueError("surface must be a non-empty name without '#' or surrounding space")
        dedupe = dedupe or DedupePolicy()
        if verifier.signed_timestamp and dedupe.replay_window is None:
            raise ValueError("a vendor with a signed timestamp must give its replay_window")
        if not verifier.signed_timestamp and dedupe.replay_window is not None:
            raise ValueError("without a signed timestamp the SEEN record never expires")
        self._surface = surface
        self._verifier = verifier
        self._store = store
        self._queue = queue
        self._metrics = metrics
        self._clock = clock
        self._dedupe = dedupe

    def handle(self, headers: Mapping[str, str], raw_body: bytes) -> IngestResponse:
        surface = self._surface
        try:
            norm = normalise_headers(headers)
            delivery_id = self._verifier.verify(norm, raw_body)
        except PermanentError:
            self._metrics.incr("webhook.rejected", surface=surface, reason="signature")
            return IngestResponse(UNAUTHORIZED, "invalid signature")
        except TransientError:
            self._metrics.incr("webhook.verify_failed", surface=surface)
            return IngestResponse(UNAVAILABLE, "try again")

        now = self._clock()
        key = Key(f"HOOK#{surface}#{delivery_id}", SEEN_SK)
        record: dict[str, object] = {"surface": surface, "seen_at": now}
        if self._dedupe.replay_window is not None:
            record["ttl"] = int(now + 2 * self._dedupe.replay_window)
        try:
            self._store.put(PLATFORM, key, record, when=Absent())
        except ConditionFailedError:
            self._metrics.incr("webhook.duplicate", surface=surface)
            return IngestResponse(DUPLICATE, "duplicate")
        except Exception:
            log.exception("webhook dedupe write failed", extra={"surface": surface})
            self._metrics.incr("webhook.store_failed", surface=surface)
            return IngestResponse(UNAVAILABLE, "try again")

        nudge = Nudge(surface, delivery_id, raw_body, norm, now)
        try:
            self._queue.enqueue(nudge)
        except Exception:
            log.exception("webhook enqueue failed", extra={"surface": surface})
            self._metrics.incr("webhook.enqueue_failed", surface=surface)
            self._release(key)
            return IngestResponse(UNAVAILABLE, "try again")
        self._metrics.incr("webhook.accepted", surface=surface)
        return IngestResponse(ACCEPTED, "accepted")

    def _release(self, key: Key) -> None:
        try:
            self._store.delete(PLATFORM, key)
        except Exception:
            log.exception("webhook dedupe release failed", extra={"surface": self._surface})
            self._metrics.incr("webhook.release_failed", surface=self._surface)
