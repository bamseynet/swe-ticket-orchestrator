"""An in-process fake of Slack: signed requests, interactive payloads, the Web API and the timing
rules for ``trigger_id`` and ``response_url`` (D7-01).

It is a SERVER and a SENDER. It signs what it sends and it does not verify: the receiver's verifier
(D7-02) is the one under test. Every ID, secret, token and URL is synthetic. Each behaviour names
the page that documents it, or says "unsourced". The live suite (D12) later proves all of it
against real Slack, and when they disagree the fake is wrong.

Sources:

* [S47] Signing. https://docs.slack.dev/authentication/verifying-requests-from-slack/ says
  ``X-Slack-Signature`` is ``v0=`` plus the hex HMAC-SHA256 of ``v0:<timestamp>:<raw body>`` under
  the signing secret, with the timestamp in ``X-Slack-Request-Timestamp`` (the receiver rejects one
  more than 5 minutes old). The fake can sign at any age, so a stale request is genuinely signed.
* [S48] Interactivity. https://docs.slack.dev/interactivity/handling-user-interaction/ says an
  interactive request is form-encoded with one ``payload`` field of JSON, needs a 200 within 3
  seconds, and carries a ``trigger_id`` and a ``response_url``. ``trigger_id`` expires in 3 seconds
  and is single use; ``response_url`` allows 5 uses within 30 minutes.
* ``views.open`` errors ``expired_trigger_id``, ``exchanged_trigger_id`` and ``invalid_trigger_id``
  are from https://docs.slack.dev/reference/methods/views.open/ .
* Events retries. https://docs.slack.dev/apis/events-api/#retries documents ``X-Slack-Retry-Num``
  and ``X-Slack-Retry-Reason``. Slack sends NO delivery ID, so none is sent here.
* Web API. https://docs.slack.dev/apis/web-api/ : an HTTP 200 with ``{"ok": false, "error": ...}``
  for method errors (``invalid_auth``, ``channel_not_found``, ``message_not_found``), and HTTP 429
  with a ``Retry-After`` header for rate limits (https://docs.slack.dev/apis/web-api/rate-limits/).
  ``chat.postMessage`` returns ``channel`` and ``ts``; ``chat.update`` edits by ``channel`` and
  ``ts`` (https://docs.slack.dev/reference/methods/chat.postMessage/).

Known departures, each deliberate:

* A ``response_url`` past its 5 uses or 30 minutes answers 404 ``used_url``. Slack's page gives the
  limits but not the response; the status and body are unsourced, observed behaviour to prove live.
  The 30 minutes run from issue, and the edge (exactly 30 minutes) is allowed: unsourced.
* ``trigger_id`` is valid for exactly 3 seconds, inclusive. The edge is unsourced.
* A trigger is never marked used when ``views.open`` fails on a bad token or an expiry.
* ``ts`` is ``<seconds>.<6-digit sequence>``, unique and ordered per fake. Real ``ts`` is unique
  per channel; the fake makes it unique globally.
* Rate limiting is injected by ``rate_limit_next``, not modelled by tier.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode

from sto.adapters.ports import RawWebhook

SIGNING_SECRET = b"synthetic-slack-signing-secret"
WRONG_SECRET = b"synthetic-not-the-secret"
BOT_TOKEN = "xoxb-synthetic-token"  # synthetic
TEAM_ID = "T0SYNTH01"  # synthetic
USER_ID = "U0SYNTH01"  # synthetic
CHANNELS = ("C1", "C2")

TRIGGER_TTL = 3.0  # seconds [S48]
RESPONSE_URL_LIMIT = 5  # uses [S48]
RESPONSE_URL_WINDOW = 30 * 60.0  # seconds [S48]
RESPONSE_URL_BASE = "https://hooks.slack.test/actions/"


@dataclass(frozen=True)
class WebResponse:
    """An HTTP answer from the fake Web API."""

    status: int
    json: Mapping[str, Any]
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class UrlResponse:
    """An HTTP answer from a ``response_url``."""

    status: int
    body: str


def _sign(secret: bytes, timestamp: str, body: bytes) -> str:
    base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret, base, hashlib.sha256).hexdigest()


class FakeSlack:
    """Slack as a sender of signed requests and a Web API server, on the shared fake ``clock``."""

    def __init__(
        self,
        clock: Callable[[], float],
        secret: bytes = SIGNING_SECRET,
        token: str = BOT_TOKEN,
    ) -> None:
        self.clock, self.secret, self.token = clock, secret, token
        self.opened_views: list[Mapping[str, Any]] = []
        self.responses: list[Mapping[str, Any]] = []
        self.messages: dict[tuple[str, str], dict[str, Any]] = {}
        self._triggers: dict[str, float] = {}  # trigger_id -> issued at
        self._used_triggers: set[str] = set()
        self._urls: dict[str, float] = {}  # response_url -> issued at
        self._uses: Counter[str] = Counter()
        self._seq = 0
        self._ts_seq = 0
        self._limit_next: list[int] = []

    # --- sending signed requests -------------------------------------------------------------

    def _headers(self, body: bytes, content_type: str, secret: bytes, age: int) -> dict[str, str]:
        timestamp = str(int(self.clock()) - age)
        return {
            "Content-Type": content_type,
            "User-Agent": "Slackbot 1.0 (+https://api.slack.com/robots)",
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": _sign(secret, timestamp, body),
        }

    def block_actions(
        self, action_id: str, *, value: str = "", timestamp_age: int = 0, user: str = USER_ID
    ) -> RawWebhook:
        """A ``block_actions`` interaction. Each one gets a fresh ``trigger_id`` (live for 3
        seconds, once) and a fresh ``response_url`` (5 uses, 30 minutes)."""
        self._seq += 1
        trigger = f"{self._seq}.{TEAM_ID}.synthtrigger{self._seq:04d}"
        url = f"{RESPONSE_URL_BASE}{TEAM_ID}/{self._seq}/synthurl{self._seq:04d}"
        now = self.clock()
        self._triggers[trigger] = now
        self._urls[url] = now
        payload = {
            "type": "block_actions",
            "user": {"id": user, "team_id": TEAM_ID},
            "team": {"id": TEAM_ID},
            "channel": {"id": CHANNELS[0]},
            "trigger_id": trigger,
            "response_url": url,
            "actions": [
                {"type": "button", "action_id": action_id, "value": value, "block_id": "b1"}
            ],
        }
        body = urlencode({"payload": json.dumps(payload)}).encode()
        headers = self._headers(
            body, "application/x-www-form-urlencoded", self.secret, timestamp_age
        )
        return RawWebhook(headers, body)

    def event(self, kind: str, *, timestamp_age: int = 0) -> RawWebhook:
        """An Events API callback (JSON). No delivery ID: Slack sends none."""
        self._seq += 1
        body = json.dumps(
            {
                "type": "event_callback",
                "team_id": TEAM_ID,
                "event": {"type": kind, "user": USER_ID, "ts": f"{int(self.clock())}.000100"},
                "event_time": int(self.clock()),
                "event_id": f"Ev{self._seq:08d}",
            }
        ).encode()
        return RawWebhook(self._headers(body, "application/json", self.secret, timestamp_age), body)

    def retry(self, raw: RawWebhook, attempt: int, reason: str = "http_timeout") -> RawWebhook:
        """The same bytes again with Slack's retry headers. The timestamp and signature are those
        of the original, as in a replay of the first request."""
        return RawWebhook(
            {**raw.headers, "X-Slack-Retry-Num": str(attempt), "X-Slack-Retry-Reason": reason},
            raw.body,
        )

    def forge(self, raw: RawWebhook) -> RawWebhook:
        """The same bytes and timestamp, signed under the wrong secret."""
        timestamp = raw.headers["X-Slack-Request-Timestamp"]
        return RawWebhook(
            {**raw.headers, "X-Slack-Signature": _sign(WRONG_SECRET, timestamp, raw.body)},
            raw.body,
        )

    @staticmethod
    def payload_of(raw: RawWebhook) -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads(parse_qs(raw.body.decode())["payload"][0])
        return loaded

    def trigger_of(self, raw: RawWebhook) -> str:
        return str(self.payload_of(raw)["trigger_id"])

    def response_url_of(self, raw: RawWebhook) -> str:
        return str(self.payload_of(raw)["response_url"])

    # --- the Web API -------------------------------------------------------------------------

    def rate_limit_next(self, retry_after: int = 1) -> None:
        """The next ``chat_post_message_response`` is a 429 with ``Retry-After``."""
        self._limit_next.append(retry_after)

    def _auth(self, token: str | None) -> dict[str, Any] | None:
        if (self.token if token is None else token) != self.token:
            return {"ok": False, "error": "invalid_auth"}
        return None

    def views_open(
        self, trigger_id: str, view: Mapping[str, Any], *, token: str | None = None
    ) -> dict[str, Any]:
        """``views.open``. A trigger works once, within 3 seconds of the interaction."""
        if (bad := self._auth(token)) is not None:
            return bad
        issued = self._triggers.get(trigger_id)
        if issued is None:
            return {"ok": False, "error": "invalid_trigger_id"}
        if trigger_id in self._used_triggers:
            return {"ok": False, "error": "exchanged_trigger_id"}
        if self.clock() - issued > TRIGGER_TTL:
            return {"ok": False, "error": "expired_trigger_id"}
        self._used_triggers.add(trigger_id)
        self.opened_views.append(view)
        return {"ok": True, "view": {"id": f"V{len(self.opened_views)}", **view}}

    def chat_post_message_response(
        self,
        channel: str,
        *,
        text: str = "",
        blocks: Sequence[Mapping[str, Any]] = (),
        token: str | None = None,
    ) -> WebResponse:
        if self._limit_next:
            wait = self._limit_next.pop(0)
            return WebResponse(
                429, {"ok": False, "error": "ratelimited"}, {"Retry-After": str(wait)}
            )
        if (bad := self._auth(token)) is not None:
            return WebResponse(200, bad)
        if channel not in CHANNELS:
            return WebResponse(200, {"ok": False, "error": "channel_not_found"})
        self._ts_seq += 1
        ts = f"{int(self.clock())}.{self._ts_seq:06d}"
        self.messages[(channel, ts)] = {"text": text, "blocks": list(blocks)}
        return WebResponse(200, {"ok": True, "channel": channel, "ts": ts})

    def chat_post_message(
        self,
        channel: str,
        *,
        text: str = "",
        blocks: Sequence[Mapping[str, Any]] = (),
        token: str | None = None,
    ) -> dict[str, Any]:
        return dict(
            self.chat_post_message_response(channel, text=text, blocks=blocks, token=token).json
        )

    def chat_update(
        self,
        channel: str,
        ts: str,
        *,
        text: str = "",
        blocks: Sequence[Mapping[str, Any]] = (),
        token: str | None = None,
    ) -> dict[str, Any]:
        if (bad := self._auth(token)) is not None:
            return bad
        if (channel, ts) not in self.messages:
            return {"ok": False, "error": "message_not_found"}
        self.messages[(channel, ts)] = {"text": text, "blocks": list(blocks)}
        return {"ok": True, "channel": channel, "ts": ts}

    # --- response_url ------------------------------------------------------------------------

    def uses(self, url: str) -> int:
        return self._uses[url]

    def post_response_url(self, url: str, body: Mapping[str, Any]) -> UrlResponse:
        """POST to a ``response_url``: 5 uses within 30 minutes of the interaction."""
        issued = self._urls.get(url)
        if issued is None:
            return UrlResponse(404, "no_such_url")
        if self.clock() - issued > RESPONSE_URL_WINDOW or self._uses[url] >= RESPONSE_URL_LIMIT:
            return UrlResponse(404, "used_url")
        self._uses[url] += 1
        self.responses.append(body)
        return UrlResponse(200, "ok")
