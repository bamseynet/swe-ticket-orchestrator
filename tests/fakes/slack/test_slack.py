"""D7-01: the fake Slack's signing and the trigger_id and response_url rules. Synthetic values."""

from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import parse_qs

import pytest

from fakes.slack import (
    RESPONSE_URL_LIMIT,
    RESPONSE_URL_WINDOW,
    SIGNING_SECRET,
    TRIGGER_TTL,
    FakeSlack,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def slack(clock: Clock) -> FakeSlack:
    return FakeSlack(clock)


VIEW = {"type": "modal", "title": {"type": "plain_text", "text": "Decide"}, "blocks": []}


def test_signature_is_v0_hmac_over_version_timestamp_raw_body(slack: FakeSlack) -> None:
    raw = slack.block_actions("approve")
    ts = raw.headers["X-Slack-Request-Timestamp"]
    base = b"v0:" + ts.encode() + b":" + raw.body
    expected = "v0=" + hmac.new(SIGNING_SECRET, base, hashlib.sha256).hexdigest()
    assert raw.headers["X-Slack-Signature"] == expected


def test_interactive_body_is_form_encoded_payload_json(slack: FakeSlack) -> None:
    raw = slack.block_actions("approve", value="gate-1")
    assert raw.headers["Content-Type"] == "application/x-www-form-urlencoded"
    payload = json.loads(parse_qs(raw.body.decode())["payload"][0])
    assert payload["type"] == "block_actions"
    assert payload["actions"][0]["action_id"] == "approve"
    assert payload["actions"][0]["value"] == "gate-1"
    assert payload["trigger_id"]
    assert payload["response_url"]
    assert "delivery_id" not in payload  # Slack sends no delivery ID
    assert "X-Slack-Delivery" not in raw.headers


def test_stale_timestamp_is_signed_genuinely(slack: FakeSlack, clock: Clock) -> None:
    raw = slack.block_actions("approve", timestamp_age=301)
    assert int(raw.headers["X-Slack-Request-Timestamp"]) == int(clock.now) - 301
    ts = raw.headers["X-Slack-Request-Timestamp"].encode()
    mac = hmac.new(SIGNING_SECRET, b"v0:" + ts + b":" + raw.body, hashlib.sha256).hexdigest()
    assert raw.headers["X-Slack-Signature"] == "v0=" + mac


def test_forged_signature_differs_only_in_signature(slack: FakeSlack) -> None:
    good = slack.block_actions("approve")
    bad = slack.forge(good)
    assert bad.body == good.body
    assert bad.headers["X-Slack-Signature"] != good.headers["X-Slack-Signature"]


def test_retry_is_same_bytes_with_retry_headers(slack: FakeSlack) -> None:
    ev = slack.event("app_mention")
    again = slack.retry(ev, attempt=1)
    assert again.body == ev.body
    assert again.headers["X-Slack-Retry-Num"] == "1"
    assert again.headers["X-Slack-Retry-Reason"] == "http_timeout"


def test_views_open_succeeds_within_three_seconds(slack: FakeSlack, clock: Clock) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    clock.now += TRIGGER_TTL
    assert slack.views_open(trigger, VIEW) == {"ok": True, "view": {"id": "V1", **VIEW}}


def test_expired_trigger_fails_as_documented(slack: FakeSlack, clock: Clock) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    clock.now += TRIGGER_TTL + 0.001
    assert slack.views_open(trigger, VIEW) == {"ok": False, "error": "expired_trigger_id"}
    assert slack.opened_views == []


def test_trigger_is_single_use(slack: FakeSlack) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    assert slack.views_open(trigger, VIEW)["ok"] is True
    assert slack.views_open(trigger, VIEW) == {"ok": False, "error": "exchanged_trigger_id"}
    assert len(slack.opened_views) == 1


def test_unknown_trigger_is_invalid(slack: FakeSlack) -> None:
    assert slack.views_open("nope", VIEW) == {"ok": False, "error": "invalid_trigger_id"}


def test_each_interaction_gets_its_own_trigger(slack: FakeSlack) -> None:
    a = slack.trigger_of(slack.block_actions("approve"))
    b = slack.trigger_of(slack.block_actions("approve"))
    assert a != b


def test_response_url_allows_five_uses(slack: FakeSlack) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    for _ in range(RESPONSE_URL_LIMIT):
        assert slack.post_response_url(url, {"text": "x"}).status == 200
    assert len(slack.responses) == RESPONSE_URL_LIMIT


def test_response_url_sixth_use_is_refused(slack: FakeSlack) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    for _ in range(RESPONSE_URL_LIMIT):
        slack.post_response_url(url, {"text": "x"})
    refused = slack.post_response_url(url, {"text": "sixth"})
    assert (refused.status, refused.body) == (404, "used_url")
    assert len(slack.responses) == RESPONSE_URL_LIMIT


def test_response_url_expires_after_thirty_minutes(slack: FakeSlack, clock: Clock) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    clock.now += RESPONSE_URL_WINDOW
    assert slack.post_response_url(url, {"text": "edge"}).status == 200
    clock.now += 1
    expired = slack.post_response_url(url, {"text": "late"})
    assert (expired.status, expired.body) == (404, "used_url")


def test_expired_url_does_not_count_a_use(slack: FakeSlack, clock: Clock) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    clock.now += RESPONSE_URL_WINDOW + 1
    slack.post_response_url(url, {"text": "late"})
    assert slack.uses(url) == 0


def test_unknown_response_url_is_404(slack: FakeSlack) -> None:
    assert slack.post_response_url("https://hooks.slack.test/actions/none", {}).status == 404


def test_post_message_returns_ts_and_update_edits_in_place(slack: FakeSlack) -> None:
    posted = slack.chat_post_message("C1", blocks=[{"type": "divider"}], text="gate")
    assert posted["ok"]
    assert posted["channel"] == "C1"
    ts = posted["ts"]
    assert slack.chat_update("C1", ts, text="closed")["ok"] is True
    assert slack.messages[("C1", ts)]["text"] == "closed"
    assert len(slack.messages) == 1


def test_update_unknown_message_fails(slack: FakeSlack) -> None:
    assert slack.chat_update("C1", "1.1", text="x") == {"ok": False, "error": "message_not_found"}


def test_message_ts_is_unique_and_ordered(slack: FakeSlack) -> None:
    a = slack.chat_post_message("C1", text="a")["ts"]
    b = slack.chat_post_message("C1", text="b")["ts"]
    assert float(b) > float(a)


def test_bad_token_is_invalid_auth(slack: FakeSlack) -> None:
    assert slack.chat_post_message("C1", text="x", token="xoxb-wrong") == {
        "ok": False,
        "error": "invalid_auth",
    }
    assert slack.views_open("t", VIEW, token="xoxb-wrong")["error"] == "invalid_auth"


def test_rate_limit_is_429_with_retry_after_and_ok_false_is_not_used(slack: FakeSlack) -> None:
    slack.rate_limit_next(retry_after=7)
    limited = slack.chat_post_message_response("C1", text="x")
    assert limited.status == 429
    assert limited.headers["Retry-After"] == "7"
    assert limited.json == {"ok": False, "error": "ratelimited"}
    assert slack.chat_post_message_response("C1", text="x").status == 200


def test_posting_to_unknown_channel_fails(slack: FakeSlack) -> None:
    assert slack.chat_post_message("C404", text="x")["error"] == "channel_not_found"


def test_docs_and_sources_are_linked() -> None:
    import fakes.slack.server as server

    doc = server.__doc__ or ""
    for url in (
        "https://docs.slack.dev/authentication/verifying-requests-from-slack/",
        "https://docs.slack.dev/interactivity/handling-user-interaction/",
        "https://docs.slack.dev/reference/methods/views.open/",
        "https://docs.slack.dev/apis/events-api/#retries",
        "https://docs.slack.dev/apis/web-api/rate-limits/",
    ):
        assert url in doc
    assert "unsourced" in doc  # departures from the docs are named
