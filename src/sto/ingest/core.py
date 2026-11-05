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
* **Size.** The queue carries at most ``SQS_MESSAGE_LIMIT`` bytes but the edge accepts far more
  (GitHub deliveries reach 25 MB), so a nudge whose body does not fit would fail on every retry.
  The body is therefore queued only when it is at most ``max_body_bytes`` (default 128 KiB, and
  never above ``MAX_BODY_BYTES_CEILING``, well below the queue limit, leaving room for headers
  and encoding). A larger one is verified on its full raw body like any other, then queued with
  ``body=b""``, ``body_omitted=True`` and its ``body_size``; the consumer re-reads state, which it
  must do anyway. The delivery stays claimed, so it is one nudge, accepted with a 202.
* **A rejected delivery claims nothing**, so guessing a delivery ID cannot block the real one.
* **Deadline.** The work is one verify, one conditional write and one enqueue; the store and queue
  adapters carry the timeouts, so a hung dependency becomes a 503 inside the vendor's deadline
  (GitHub: 10 seconds, ADR-0016) rather than a vendor-side timeout.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sto.domain.errors import PermanentError, TransientError
from sto.store.ports import (
    PLATFORM,
    Absent,
    ConditionFailedError,
    Key,
    Store,
    TransactionOutcomeUnknownError,
)

log = logging.getLogger(__name__)

ACCEPTED = 202
DUPLICATE = 200
UNAUTHORIZED = 401
UNAVAILABLE = 503

SEEN_SK = "SEEN"
MAX_DELIVERY_ID_CHARS = 512
# Never queued: the nudge and its dead-letter queue are read by more people and tools than the
# vendor's endpoint is. A verifier adds the vendor's own secret headers via ``secret_headers``.
SQS_MESSAGE_LIMIT = 256 * 1024
MAX_BODY_BYTES_CEILING = 192 * 1024
DEFAULT_MAX_BODY_BYTES = 128 * 1024
CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


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

    ``replay_window`` is the number of seconds the verifier accepts a signed timestamp for, or
    None if the signature covers no timestamp (``signed_timestamp`` False). Ingest derives the
    dedupe record's TTL from it, so the record outlives every replay the verifier would still
    accept; with None the record never expires. The two must agree (ingest refuses a mismatch).

    ``secret_headers`` are lower-case names of the vendor's own credential headers, which ingest
    keeps out of the queued nudge (on top of ``CREDENTIAL_HEADERS``).
    """

    signed_timestamp: bool
    replay_window: float | None
    secret_headers: frozenset[str]

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str: ...


@dataclass(frozen=True)
class Nudge:
    """What is queued: that something changed. Never the truth. ``reread`` is always True.

    ``body`` is the raw delivery only when it fit under the ingest's size limit. Otherwise it is
    empty and ``body_omitted`` is True; ``body_size`` is the delivery's real size either way.
    ``event`` is the vendor's event name from the configured event header, if any.
    """

    surface: str
    delivery_id: str
    body: bytes
    headers: Mapping[str, str]
    received_at: float
    reread: bool = True
    body_omitted: bool = False
    body_size: int = 0
    event: str | None = None

    def __post_init__(self) -> None:
        if self.reread is not True:
            raise ValueError("a webhook delivery is a nudge: consumers must re-read state")
        if self.body_omitted:
            if self.body:
                raise ValueError("a nudge that omits its body must carry no body")
        elif self.body_size != len(self.body):
            raise ValueError("body_size must match a carried body")


class NudgeQueue(Protocol):
    def enqueue(self, nudge: Nudge) -> None:
        """Raise on any failure; ingest then answers 503 so the vendor retries."""
        ...


class Metrics(Protocol):
    def incr(self, name: str, **tags: str) -> None: ...


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
        if not isinstance(name, str) or not isinstance(value, str):
            raise PermanentError("header names and values must be strings")
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
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        event_header: str | None = None,
    ) -> None:
        if not 0 < max_body_bytes <= MAX_BODY_BYTES_CEILING:
            raise ValueError(
                f"max_body_bytes must be between 1 and {MAX_BODY_BYTES_CEILING}, "
                f"well below the queue limit of {SQS_MESSAGE_LIMIT}"
            )
        self._max_body = max_body_bytes
        self._event_header = event_header.strip().lower() if event_header else None
        if not surface or surface != surface.strip() or "#" in surface:
            raise ValueError("surface must be a non-empty name without '#' or surrounding space")
        window = verifier.replay_window
        if verifier.signed_timestamp and window is None:
            raise ValueError("a vendor with a signed timestamp must declare its replay_window")
        if not verifier.signed_timestamp and window is not None:
            raise ValueError("without a signed timestamp the SEEN record never expires")
        if window is not None and not window > 0:
            raise ValueError("replay_window must be positive")
        self._window = window
        self._secret_headers = CREDENTIAL_HEADERS | verifier.secret_headers
        self._surface = surface
        self._verifier = verifier
        self._store = store
        self._queue = queue
        self._metrics = metrics
        self._clock = clock

    def handle(self, headers: Mapping[str, str], raw_body: bytes) -> IngestResponse:
        surface = self._surface
        try:
            norm = normalise_headers(headers)
        except PermanentError:
            self._metrics.incr("webhook.rejected", surface=surface, reason="headers")
            return IngestResponse(UNAUTHORIZED, "invalid headers")
        try:
            delivery_id = self._verifier.verify(norm, raw_body)
        except PermanentError:
            self._metrics.incr("webhook.rejected", surface=surface, reason="signature")
            return IngestResponse(UNAUTHORIZED, "invalid signature")
        except TransientError:
            self._metrics.incr("webhook.verify_failed", surface=surface)
            return IngestResponse(UNAVAILABLE, "try again")
        except Exception:
            # A verifier bug stays loud (the platform's 5xx makes the vendor retry), but counted.
            self._metrics.incr("webhook.verify_error", surface=surface)
            raise
        if (
            not isinstance(delivery_id, str)
            or not delivery_id.strip()
            or len(delivery_id) > MAX_DELIVERY_ID_CHARS
        ):
            # An empty ID would be one shared key, dropping every later ID-less delivery.
            self._metrics.incr("webhook.rejected", surface=surface, reason="delivery_id")
            return IngestResponse(UNAUTHORIZED, "invalid delivery id")

        now = self._clock()
        key = Key(f"HOOK#{surface}#{delivery_id}", SEEN_SK)
        record: dict[str, object] = {"surface": surface, "seen_at": now}
        if self._window is not None:
            record["ttl"] = math.ceil(now + 2 * self._window)
        try:
            self._store.put(PLATFORM, key, record, when=Absent())
        except ConditionFailedError:
            self._metrics.incr("webhook.duplicate", surface=surface)
            return IngestResponse(DUPLICATE, "duplicate")
        except TransactionOutcomeUnknownError:
            # The claim may have landed with its answer lost: release it, else the vendor's retry
            # is dropped as a duplicate and the nudge is gone. A second nudge is harmless.
            log.exception("webhook dedupe write outcome unknown", extra={"surface": surface})
            self._metrics.incr("webhook.store_failed", surface=surface)
            self._release(key)
            return IngestResponse(UNAVAILABLE, "try again")
        except Exception:
            log.exception("webhook dedupe write failed", extra={"surface": surface})
            self._metrics.incr("webhook.store_failed", surface=surface)
            return IngestResponse(UNAVAILABLE, "try again")

        safe = {k: v for k, v in norm.items() if k not in self._secret_headers}
        size = len(raw_body)
        omit = size > self._max_body
        event = norm.get(self._event_header) if self._event_header else None
        nudge = Nudge(
            surface,
            delivery_id,
            b"" if omit else raw_body,
            safe,
            now,
            body_omitted=omit,
            body_size=size,
            event=event or None,
        )
        try:
            self._queue.enqueue(nudge)
        except Exception:
            log.exception("webhook enqueue failed", extra={"surface": surface})
            self._metrics.incr("webhook.enqueue_failed", surface=surface)
            self._release(key)
            return IngestResponse(UNAVAILABLE, "try again")
        if omit:
            self._metrics.incr("webhook.body_omitted", surface=surface)
        self._metrics.incr("webhook.accepted", surface=surface)
        return IngestResponse(ACCEPTED, "accepted")

    def _release(self, key: Key) -> None:
        try:
            self._store.delete(PLATFORM, key)
        except Exception:
            log.exception("webhook dedupe release failed", extra={"surface": self._surface})
            self._metrics.incr("webhook.release_failed", surface=self._surface)
