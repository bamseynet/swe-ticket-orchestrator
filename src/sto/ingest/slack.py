"""Slack verification and the ack path (D7-02, ADR-0009): a thin vendor layer over ingest core.

Kept light on purpose: only the standard library and ``sto.ingest.core`` are imported, so a cold
start of the Slack function stays far inside Slack's 3 second deadline (a test measures it and
lists the modules that must not load).

* **Verification** (https://docs.slack.dev/authentication/verifying-requests-from-slack/): the
  signature is ``v0=`` plus the hex HMAC-SHA256 of ``v0:<timestamp>:<raw body>`` under the signing
  secret. It is computed over the RAW bytes before anything is parsed (PLAN T6). A timestamp more
  than 5 minutes from the clock, in either direction, is refused. The comparison is constant time.
* **Dedupe key.** Slack sends no delivery ID, so the key is derived from the verified body:
  an Events API callback uses ``event:<event_id>`` (a retry is re-signed with a fresh timestamp
  but keeps its ``event_id``, so it lands on the same record); an interaction uses
  ``interaction:<trigger_id>``, which Slack issues afresh for every click, so two clicks of one
  button are two deliveries while a byte-identical redelivery is one. A body that lacks the field
  falls back to ``<kind>:sha256:<hex of the raw body>``. The ID is a dedupe key only, never a
  fact: the consumer re-reads state (``Nudge.reread``). ``trigger_id`` is used as an opaque key
  here and its 3 second expiry is not checked: that is D7-04's business at ``views.open``.
* **Ack.** Slack wants a 2xx inside 3 seconds and retries anything else. ``202`` (queued) is
  answered ``200`` with an empty body, and a duplicate is ``200`` too so Slack stops retrying.
  A bad signature is ``401`` and a failed store or queue is ``503`` (Slack retries).
* ``url_verification`` (https://docs.slack.dev/reference/events/url_verification/) is verified
  like any request, then answered with its ``challenge`` and never queued.
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
from typing import Any, Literal
from urllib.parse import parse_qs

from sto.domain.errors import PermanentError
from sto.ingest.core import (
    ACCEPTED,
    DUPLICATE,
    UNAUTHORIZED,
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

_TIMESTAMP = re.compile(r"[0-9]{1,12}", re.ASCII)
_SAFE_ID = re.compile(r"[A-Za-z0-9_.\-]{1,128}", re.ASCII)

Kind = Literal["events", "interactivity"]


def _body_hash(raw_body: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw_body).hexdigest()


def _safe_id(value: object) -> str | None:
    if isinstance(value, str) and _SAFE_ID.fullmatch(value):
        return value
    return None


def _events_id(raw_body: bytes) -> str:
    try:
        obj = json.loads(raw_body)
    except ValueError as exc:
        raise PermanentError("malformed event body") from exc
    if not isinstance(obj, dict):
        raise PermanentError("malformed event body")
    if obj.get("type") == "url_verification":
        return "handshake:" + _body_hash(raw_body)
    if "event_id" not in obj:
        return "event:" + _body_hash(raw_body)
    event_id = _safe_id(obj["event_id"])
    if event_id is None:
        raise PermanentError("malformed event_id")
    return "event:" + event_id


def _interaction_payload(raw_body: bytes) -> dict[str, Any]:
    try:
        fields = parse_qs(raw_body.decode("ascii"), keep_blank_values=True)
        (text,) = fields["payload"]
        payload = json.loads(text)
    except (ValueError, KeyError, UnicodeError) as exc:
        raise PermanentError("malformed interaction body") from exc
    if not isinstance(payload, dict):
        raise PermanentError("malformed interaction body")
    return payload


def _interaction_id(raw_body: bytes) -> str:
    payload = _interaction_payload(raw_body)
    if "trigger_id" not in payload:
        return "interaction:" + _body_hash(raw_body)
    trigger = _safe_id(payload["trigger_id"])
    if trigger is None:
        raise PermanentError("malformed trigger_id")
    return "interaction:" + trigger


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
        return _delivery_id(self._kind, raw_body)


def _delivery_id(kind: Kind, raw_body: bytes) -> str:
    return _events_id(raw_body) if kind == "events" else _interaction_id(raw_body)


def _ack(response: IngestResponse) -> IngestResponse:
    """Slack wants a plain 2xx: queued is 200 with nothing in the body."""
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
        self._events_verifier = SlackVerifier(signing_secret, clock, kind="events")
        self._events = WebhookIngest(
            EVENTS_SURFACE, self._events_verifier, store, queue, metrics, clock=clock
        )
        self._interactive = WebhookIngest(
            INTERACTIVE_SURFACE,
            SlackVerifier(signing_secret, clock, kind="interactivity"),
            store,
            queue,
            metrics,
            clock=clock,
        )

    def events(self, headers: Mapping[str, str], raw_body: bytes) -> IngestResponse:
        if b"url_verification" in raw_body:
            challenge = self._handshake(headers, raw_body)
            if challenge is not None:
                return challenge
        return _ack(self._events.handle(headers, raw_body))

    def interactivity(self, headers: Mapping[str, str], raw_body: bytes) -> IngestResponse:
        return _ack(self._interactive.handle(headers, raw_body))

    def _handshake(self, headers: Mapping[str, str], raw_body: bytes) -> IngestResponse | None:
        """Answer a verified ``url_verification`` with its challenge; None if it is not one."""
        try:
            self._events_verifier.verify(normalise_headers(headers), raw_body)
        except PermanentError:
            self._metrics.incr("webhook.rejected", surface=EVENTS_SURFACE, reason="signature")
            return IngestResponse(UNAUTHORIZED, "invalid signature")
        try:
            obj = json.loads(raw_body)
        except ValueError:
            return None  # signed but not JSON: the normal path refuses it
        if isinstance(obj, dict) and obj.get("type") == "url_verification":
            challenge = obj.get("challenge")
            if isinstance(challenge, str):
                return IngestResponse(200, challenge)
        return None
