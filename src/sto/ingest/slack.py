"""Slack verification and the ack path (D7-02, ADR-0009): a thin vendor layer over ingest core.

Kept light on purpose: only the standard library and ``sto`` modules that themselves import only
the standard library are loaded, so a cold start of the Slack function stays far inside Slack's
3 second deadline (a test measures it and rejects any third-party import).

* **Verification** (https://docs.slack.dev/authentication/verifying-requests-from-slack/): the
  signature is ``v0=`` plus the lower-case hex HMAC-SHA256 of ``v0:<timestamp>:<raw body>`` under
  the signing secret. It is computed over the RAW bytes before anything is parsed (PLAN T6). The
  timestamp must be plain ASCII digits, and one more than 5 minutes from the clock, in either
  direction, is refused. The comparison is constant time.
* **Dedupe key.** Slack sends no delivery ID, so the key comes from the verified body. An Events
  API callback uses its ``event_id``, prefixed ``<api_app_id>:`` when the body carries one, so two
  apps cannot share a namespace (a retry is re-signed with a fresh timestamp but keeps its
  ``event_id``, so it lands on the same record). An interaction uses its ``trigger_id``, which
  Slack issues afresh for every click: two clicks of one button are two deliveries, and a
  byte-identical redelivery is one. Events and interactions are separate surfaces, so their keys
  never meet. A body without the field is MALFORMED and refused: no key is ever invented from the
  body (the suite requires it). The key is a dedupe key only, never a fact: the consumer re-reads
  state (``Nudge.reread``). ``trigger_id`` is an opaque key here; its 3 second expiry is checked
  by nobody on this path (D7-04 meets it at ``views.open``).
* **Ack.** Slack wants a 2xx inside 3 seconds and retries anything else. Queued and duplicate are
  both ``200`` with an empty body. A bad signature or stale timestamp is ``401``, a genuine but
  malformed body is ``400`` (counted ``reason=malformed``, never ``signature``), and a failed store
  or queue is ``503`` (Slack retries).
* ``app_rate_limited`` is Slack's own notice that the app is throttled. It has no ``event_id`` and
  is not an event to act on: it is answered 200 (a 4xx would count against the app), counted
  ``webhook.ignored reason=rate_limited`` and never queued. IDs may not contain ``:``, so the
  ``<api_app_id>:<event_id>`` key cannot collide (``A:B`` + ``C`` against ``A`` + ``B:C``).
* The timestamp has one spelling (no leading zero), so no two header values mean one instant.
* ``url_verification`` (https://docs.slack.dev/reference/events/url_verification/) is decided from
  the verified, parsed body: it is answered with its string ``challenge`` and never queued. One
  without a string ``challenge`` is malformed.
* Interactivity is its own small function (``SlackIngest.interactivity``) on its own surface
  (``slack.interactive``): a form body with one ``payload`` field of JSON.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import parse_qs

from sto.adapters.ports import MalformedWebhookError
from sto.domain.errors import PermanentError
from sto.ingest.core import (
    ACCEPTED,
    DUPLICATE,
    IngestResponse,
    Metrics,
    NudgeQueue,
    WebhookIngest,
    normalise_headers,
)
from sto.store.ports import Store

EVENTS_SURFACE = "slack"
INTERACTIVE_SURFACE = "slack.interactive"
REPLAY_WINDOW = 300.0  # seconds, either direction
SIGNATURE_HEADER = "x-slack-signature"
TIMESTAMP_HEADER = "x-slack-request-timestamp"
VERSION = "v0"
MALFORMED = 400

_TIMESTAMP = re.compile(r"[1-9][0-9]{0,11}", re.ASCII)  # no leading zero: one spelling each
_SAFE_ID = re.compile(r"[A-Za-z0-9_.\-]{1,128}", re.ASCII)

Kind = Literal["events", "interactivity"]


@dataclass(frozen=True)
class Verified:
    """A genuine delivery, parsed. ``challenge`` is set for ``url_verification`` only, and
    ``rate_limited`` for Slack's own ``app_rate_limited`` notice. Neither has a delivery ID."""

    delivery_id: str
    challenge: str | None = None
    rate_limited: bool = False


def _safe_id(value: object, what: str) -> str:
    if isinstance(value, str) and _SAFE_ID.fullmatch(value):
        return value
    raise MalformedWebhookError(f"missing or malformed {what}")


def _parse_events(raw_body: bytes) -> Verified:
    try:
        obj = json.loads(raw_body)
    except (ValueError, RecursionError) as exc:  # deep nesting from a genuine signer
        raise MalformedWebhookError("event body is not JSON") from exc
    if not isinstance(obj, dict):
        raise MalformedWebhookError("event body is not an object")
    if obj.get("type") == "url_verification":
        challenge = obj.get("challenge")
        if not isinstance(challenge, str):
            raise MalformedWebhookError("url_verification without a string challenge")
        return Verified("", challenge)
    if obj.get("type") == "app_rate_limited":
        return Verified("", rate_limited=True)
    event_id = _safe_id(obj.get("event_id"), "event_id")
    if "api_app_id" not in obj:
        return Verified(event_id)
    return Verified(_safe_id(obj["api_app_id"], "api_app_id") + ":" + event_id)


def _parse_interaction(raw_body: bytes) -> Verified:
    try:
        fields = parse_qs(raw_body.decode("ascii"), keep_blank_values=True)
        (text,) = fields["payload"]
        payload: Any = json.loads(text)
    except (ValueError, KeyError, UnicodeError, RecursionError) as exc:
        raise MalformedWebhookError("interaction body has no single JSON payload") from exc
    if not isinstance(payload, dict):
        raise MalformedWebhookError("interaction payload is not an object")
    return Verified(_safe_id(payload.get("trigger_id"), "trigger_id"))


class SlackVerifier:
    """Slack's ``v0`` signature, on the raw body, with a 5 minute window. Implements the
    ``WebhookVerifier`` port: the delivery ID it returns is the dedupe key described above."""

    signed_timestamp = True
    replay_window: float | None = REPLAY_WINDOW
    secret_headers: frozenset[str] = frozenset({SIGNATURE_HEADER})

    def __init__(
        self,
        signing_secret: bytes,
        clock: Callable[[], float] = time.time,
        *,
        kind: Kind,
    ) -> None:
        if not signing_secret:
            raise ValueError("a signing secret is required")
        self._secret = signing_secret
        self._clock = clock
        self._kind = kind

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        """The delivery ID. A handshake has none, so it is refused here: it is never queued."""
        verified = self.parse(headers, raw_body)
        if verified.challenge is not None or verified.rate_limited:
            raise MalformedWebhookError("a handshake or rate-limit notice is not a delivery")
        return verified.delivery_id

    def parse(self, headers: Mapping[str, str], raw_body: bytes) -> Verified:
        """Authenticate on the raw bytes, and only then read the body."""
        self._authenticate(normalise_headers(headers), raw_body)  # idempotent on core's output
        if self._kind == "events":
            return _parse_events(raw_body)
        return _parse_interaction(raw_body)

    def _authenticate(self, headers: Mapping[str, str], raw_body: bytes) -> None:
        """The only function that computes the MAC. It compares nothing but through
        ``hmac.compare_digest`` (a test checks this statically)."""
        stamp = headers.get(TIMESTAMP_HEADER, "")
        if _TIMESTAMP.fullmatch(stamp) is None:
            raise PermanentError("missing or malformed timestamp")
        signed = VERSION.encode() + b":" + stamp.encode() + b":" + raw_body
        digest = hmac.new(self._secret, signed, hashlib.sha256).hexdigest()
        expected = (VERSION + "=" + digest).encode()
        given = headers.get(SIGNATURE_HEADER, "").encode("utf-8", "replace")
        if not hmac.compare_digest(given, expected):
            raise PermanentError("bad signature")
        if abs(self._clock() - int(stamp)) > REPLAY_WINDOW:
            raise PermanentError("timestamp outside the replay window")


def _ack(response: IngestResponse) -> IngestResponse:
    """Slack wants a plain 2xx: queued and duplicate are both 200 with nothing in the body."""
    if response.status in (ACCEPTED, DUPLICATE):
        return IngestResponse(200, "")
    return response


class SlackIngest:
    """The two Slack endpoints: ``events`` (Events API) and ``interactivity`` (button clicks)."""

    def __init__(
        self,
        signing_secret: bytes,
        store: Store,
        queue: NudgeQueue,
        metrics: Metrics,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._metrics = metrics
        self.events_verifier = SlackVerifier(signing_secret, clock, kind="events")
        self.interactivity_verifier = SlackVerifier(signing_secret, clock, kind="interactivity")
        self._events = WebhookIngest(
            EVENTS_SURFACE, self.events_verifier, store, queue, metrics, clock=clock
        )
        self._interactive = WebhookIngest(
            INTERACTIVE_SURFACE, self.interactivity_verifier, store, queue, metrics, clock=clock
        )

    def events(self, headers: Mapping[str, str], raw_body: bytes) -> IngestResponse:
        verified, early = self._screen(self.events_verifier, EVENTS_SURFACE, headers, raw_body)
        if early is not None:
            return early
        if verified is not None and verified.challenge is not None:
            return IngestResponse(200, verified.challenge)  # a verified handshake, never queued
        if verified is not None and verified.rate_limited:
            # Slack's own notice has no event_id: 400 would count as a failed delivery. Ack it,
            # queue nothing, and count it so an operator sees the app is being throttled.
            self._metrics.incr("webhook.ignored", surface=EVENTS_SURFACE, reason="rate_limited")
            return IngestResponse(200, "")
        return _ack(self._events.handle(headers, raw_body))

    def interactivity(self, headers: Mapping[str, str], raw_body: bytes) -> IngestResponse:
        _, early = self._screen(self.interactivity_verifier, INTERACTIVE_SURFACE, headers, raw_body)
        if early is not None:
            return early
        return _ack(self._interactive.handle(headers, raw_body))

    def _screen(
        self,
        verifier: SlackVerifier,
        surface: str,
        headers: Mapping[str, str],
        raw_body: bytes,
    ) -> tuple[Verified | None, IngestResponse | None]:
        """Tell a genuine but malformed body (400, ``reason=malformed``) from a bad signature
        (core answers 401 and counts it). Anything else is left to core, which re-verifies: a
        second HMAC is microseconds, and keeps core the only place that claims a dedupe record."""
        try:
            return verifier.parse(headers, raw_body), None
        except MalformedWebhookError:
            self._metrics.incr("webhook.rejected", surface=surface, reason="malformed")
            return None, IngestResponse(MALFORMED, "malformed")
        except PermanentError:
            return None, None
