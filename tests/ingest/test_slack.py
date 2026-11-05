"""D7-02: Slack verification and the ack path. Synthetic secrets, the D7-01 fake as the sender.

The signature is checked on the raw bytes (the fake's bytes are deliberately non-canonical), a
request more than 5 minutes from the clock is refused, a retry is deduped on ``event_id``, and an
interaction on its ``trigger_id`` (which the suite only READS, as a key: its 3 second expiry is the
fake's and D7-04's business). Slack has no delivery ID, so the key is what these tests pin.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import inspect
import subprocess
import sys
import time
from collections.abc import Mapping
from urllib.parse import urlencode

import pytest

from contract.suite import CAPABILITIES, Vendor
from fakes.slack import CHANNELS, SIGNING_SECRET, WRONG_SECRET, FakeSlack
from sto.adapters.ports import RawWebhook
from sto.ingest import slack as slack_module
from sto.ingest.core import Nudge
from sto.ingest.slack import SlackIngest, SlackVerifier
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, Key

NOW = 1_700_000_000.0


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


class Queue:
    def __init__(self) -> None:
        self.items: list[Nudge] = []

    def enqueue(self, nudge: Nudge) -> None:
        self.items.append(nudge)


class Metrics:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def incr(self, name: str, **tags: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1


class Rig:
    def __init__(self) -> None:
        self.clock = Clock()
        self.store = MemoryStore()
        self.queue = Queue()
        self.metrics = Metrics()
        self.slack = FakeSlack(self.clock)
        self.ingest = SlackIngest(
            SIGNING_SECRET, self.store, self.queue, self.metrics, clock=self.clock
        )

    def events(self, raw: RawWebhook) -> tuple[int, str]:
        r = self.ingest.events(raw.headers, raw.body)
        return r.status, r.body

    def interact(self, raw: RawWebhook) -> tuple[int, str]:
        r = self.ingest.interactivity(raw.headers, raw.body)
        return r.status, r.body


@pytest.fixture
def rig() -> Rig:
    return Rig()


def signed(body: bytes, ts: float = NOW, secret: bytes = SIGNING_SECRET) -> RawWebhook:
    stamp = str(int(ts))
    mac = hmac.new(secret, b"v0:" + stamp.encode() + b":" + body, hashlib.sha256).hexdigest()
    return RawWebhook({"X-Slack-Request-Timestamp": stamp, "X-Slack-Signature": "v0=" + mac}, body)


# --- acknowledgement ----------------------------------------------------------------------------


def test_genuine_event_is_acked_200_and_queued_with_its_raw_bytes(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    assert rig.events(raw) == (200, "")
    (nudge,) = rig.queue.items
    assert nudge.body == raw.body
    assert nudge.reread is True
    assert nudge.surface == "slack"


def test_genuine_interaction_is_acked_200_and_queued(rig: Rig) -> None:
    raw = rig.slack.block_actions("approve", value="g1")
    assert rig.interact(raw) == (200, "")
    (nudge,) = rig.queue.items
    assert nudge.body == raw.body
    assert nudge.surface == "slack.interactive"


def test_credential_header_is_not_queued(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    rig.events(raw)
    assert "x-slack-signature" not in rig.queue.items[0].headers


def test_form_body_with_plus_or_percent20_spaces_is_decoded(rig: Rig) -> None:
    payload = (
        '{"type":"block_actions","trigger_id":"1.2.abc","user":{"id":"U1"},'
        '"actions":[{"action_id":"a b"}]}'
    )
    body = urlencode({"payload": payload}).encode()  # '+' for spaces
    assert b"+" in body
    assert rig.interact(signed(body))[0] == 200
    assert rig.queue.items[0].delivery_id == "interaction:1.2.abc"


# --- verification -------------------------------------------------------------------------------


@pytest.mark.parametrize("age", [301, 3600])
def test_old_timestamps_are_refused(rig: Rig, age: int) -> None:
    raw = rig.slack.event("app_mention", timestamp_age=age)
    assert rig.events(raw)[0] == 401
    assert rig.queue.items == []
    assert rig.metrics.counts["webhook.rejected"] == 1


def test_timestamps_exactly_five_minutes_off_are_accepted_either_way(rig: Rig) -> None:
    assert rig.events(rig.slack.event("app_mention", timestamp_age=300))[0] == 200
    assert rig.events(rig.slack.event("app_mention", timestamp_age=-300))[0] == 200


def test_a_timestamp_in_the_future_beyond_the_window_is_refused(rig: Rig) -> None:
    assert rig.events(rig.slack.event("app_mention", timestamp_age=-301))[0] == 401


def test_old_interaction_is_refused(rig: Rig) -> None:
    assert rig.interact(rig.slack.block_actions("approve", timestamp_age=301))[0] == 401
    assert rig.queue.items == []


def test_forged_signature_is_refused(rig: Rig) -> None:
    assert rig.events(rig.slack.forge(rig.slack.event("app_mention")))[0] == 401
    assert rig.interact(rig.slack.forge(rig.slack.block_actions("a")))[0] == 401
    assert rig.queue.items == []


def test_tampered_body_is_refused(rig: Rig) -> None:
    assert rig.events(rig.slack.tamper(rig.slack.event("app_mention")))[0] == 401
    assert rig.interact(rig.slack.tamper(rig.slack.block_actions("a")))[0] == 401


def test_the_signature_is_over_the_raw_bytes_not_a_re_encoding(rig: Rig) -> None:
    ev = rig.slack.event("app_mention")
    assert rig.slack.reserialise(ev).body != ev.body
    assert rig.events(rig.slack.reserialise(ev))[0] == 401
    ba = rig.slack.block_actions("a")
    assert rig.interact(rig.slack.reserialise(ba))[0] == 401
    # and the genuine non-canonical bytes pass
    assert rig.events(ev)[0] == 200


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h: {k: v for k, v in h.items() if k != "X-Slack-Signature"},
        lambda h: {k: v for k, v in h.items() if k != "X-Slack-Request-Timestamp"},
        lambda h: {**h, "X-Slack-Signature": "v1=" + h["X-Slack-Signature"][3:]},
        lambda h: {**h, "X-Slack-Signature": h["X-Slack-Signature"][3:]},
        lambda h: {**h, "X-Slack-Signature": h["X-Slack-Signature"][:-2]},
        lambda h: {**h, "X-Slack-Signature": ""},
        lambda h: {**h, "X-Slack-Signature": "v0=é"},
        lambda h: {**h, "X-Slack-Request-Timestamp": "abc"},
        lambda h: {**h, "X-Slack-Request-Timestamp": ""},
        lambda h: {**h, "X-Slack-Request-Timestamp": "-1"},
        lambda h: {**h, "X-Slack-Request-Timestamp": "1e9"},
        lambda h: {**h, "X-Slack-Request-Timestamp": "١٢٣"},
    ],
)
def test_malformed_headers_are_refused(rig: Rig, mutate: object) -> None:
    raw = rig.slack.event("app_mention")
    headers: Mapping[str, str] = mutate(dict(raw.headers))  # type: ignore[operator]
    assert rig.ingest.events(headers, raw.body).status == 401
    assert rig.queue.items == []


def test_a_wrong_secret_is_refused() -> None:
    other = Rig()
    other.ingest = SlackIngest(
        WRONG_SECRET, other.store, other.queue, other.metrics, clock=other.clock
    )
    assert other.events(other.slack.event("app_mention"))[0] == 401


def test_signed_but_malformed_bodies_are_refused(rig: Rig) -> None:
    assert rig.ingest.events(*_parts(signed(b"not json"))).status == 401
    assert rig.ingest.events(*_parts(signed(b"[1]"))).status == 401
    assert rig.ingest.interactivity(*_parts(signed(b"payload="))).status == 401
    assert rig.ingest.interactivity(*_parts(signed(b"other=1"))).status == 401
    assert rig.ingest.interactivity(*_parts(signed(b"payload=%7B"))).status == 401
    assert rig.queue.items == []


def _parts(raw: RawWebhook) -> tuple[Mapping[str, str], bytes]:
    return raw.headers, raw.body


def test_an_event_body_on_the_interactivity_path_is_refused(rig: Rig) -> None:
    assert rig.interact(rig.slack.event("app_mention"))[0] == 401
    assert rig.events(rig.slack.block_actions("a"))[0] == 401


def test_verifier_declares_the_window_slack_signs_and_agrees_with_the_contract_suite() -> None:
    v = SlackVerifier(SIGNING_SECRET, Clock(), kind="events")
    caps = CAPABILITIES[Vendor.SLACK]
    assert v.replay_window == 300.0
    assert v.signed_timestamp is True
    assert caps.signed_timestamp is True
    assert "x-slack-signature" in v.secret_headers


def test_dedupe_record_expires_past_twice_the_window(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    rig.events(raw)
    eid = rig.queue.items[0].delivery_id
    item = rig.store.get(PLATFORM, Key(f"HOOK#slack#{eid}", "SEEN"))
    assert item is not None
    assert item.data["ttl"] == int(NOW + 600)


def test_signature_comparison_is_constant_time_no_equality_operators() -> None:
    """D4-04's review: no ==/!= on any value in a function that computes an HMAC."""
    tree = ast.parse(inspect.getsource(slack_module))
    seen = 0
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        if "hmac" not in ast.unparse(fn):
            continue
        seen += 1
        for node in ast.walk(fn):
            if isinstance(node, ast.Compare):
                assert not any(isinstance(op, ast.Eq | ast.NotEq) for op in node.ops), fn.name
    assert seen >= 1
    assert "compare_digest" in inspect.getsource(slack_module)


# --- url_verification ---------------------------------------------------------------------------


def test_url_verification_echoes_the_challenge_and_queues_nothing(rig: Rig) -> None:
    status, body = rig.events(rig.slack.url_verification("abc-123"))
    assert (status, body) == (200, "abc-123")
    assert rig.queue.items == []


def test_url_verification_is_verified_first(rig: Rig) -> None:
    raw = rig.slack.forge(rig.slack.url_verification("abc-123"))
    assert rig.events(raw) == (401, "invalid signature")
    old = rig.slack.url_verification("abc-123")
    stale = RawWebhook({**old.headers, "X-Slack-Request-Timestamp": str(int(NOW) - 400)}, old.body)
    assert rig.events(stale)[0] == 401


# --- retries and the dedupe key -----------------------------------------------------------------


def test_retries_are_deduped_on_event_id_though_re_signed_with_a_fresh_timestamp(
    rig: Rig,
) -> None:
    first = rig.slack.event("app_mention")
    assert rig.events(first)[0] == 200
    rig.clock.now += 100
    one = rig.slack.retry(first, 1)
    two = rig.slack.retry(first, 2, reason="http_error")
    assert one.headers["X-Slack-Request-Timestamp"] != first.headers["X-Slack-Request-Timestamp"]
    assert one.headers["X-Slack-Signature"] != first.headers["X-Slack-Signature"]
    assert rig.events(one) == (200, "")
    assert rig.events(two) == (200, "")
    assert len(rig.queue.items) == 1
    assert rig.metrics.counts["webhook.duplicate"] == 2


def test_the_dedupe_key_is_unique_per_delivery_and_stable_across_retries(rig: Rig) -> None:
    events = [rig.slack.event("app_mention", channel=CHANNELS[i % 2]) for i in range(25)]
    interactions = [rig.slack.block_actions("approve", value="same") for _ in range(25)]
    for raw in events:
        assert rig.events(raw)[0] == 200
    for raw in interactions:
        assert rig.interact(raw)[0] == 200
    ids = [n.delivery_id for n in rig.queue.items]
    assert len(ids) == 50
    assert len(set(ids)) == 50  # every delivery its own key
    # a retry of each event lands on the key it already holds
    for raw in events:
        assert rig.events(rig.slack.retry(raw, 1))[0] == 200
    assert len(rig.queue.items) == 50
    # a retry's key is the original's, not merely a distinct one
    assert {n.delivery_id for n in rig.queue.items if n.surface == "slack"} == {
        f"event:Ev{i:08d}" for i in range(1, 26)
    }


def test_two_clicks_of_the_same_button_are_two_deliveries(rig: Rig) -> None:
    a = rig.slack.block_actions("approve", value="g1")
    b = rig.slack.block_actions("approve", value="g1")
    assert rig.interact(a)[0] == rig.interact(b)[0] == 200
    assert len(rig.queue.items) == 2


def test_the_same_interaction_delivered_twice_is_deduped(rig: Rig) -> None:
    a = rig.slack.block_actions("approve")
    rig.interact(a)
    assert rig.interact(a) == (200, "")
    assert len(rig.queue.items) == 1


def test_an_interaction_without_a_trigger_id_is_keyed_by_body_hash(rig: Rig) -> None:
    body = urlencode({"payload": '{"type":"view_closed","user":{"id":"U1"}}'}).encode()
    rig.interact(signed(body))
    assert (
        rig.queue.items[0].delivery_id == "interaction:sha256:" + hashlib.sha256(body).hexdigest()
    )


def test_an_event_without_event_id_is_keyed_by_body_hash(rig: Rig) -> None:
    body = b'{"type":"app_rate_limited","team_id":"T1"}'
    rig.events(signed(body))
    assert rig.queue.items[0].delivery_id == "event:sha256:" + hashlib.sha256(body).hexdigest()


def test_a_hostile_event_id_cannot_forge_a_key_with_a_separator(rig: Rig) -> None:
    body = b'{"type":"event_callback","event_id":"x#y"}'
    assert rig.events(signed(body))[0] == 401


def test_a_rejected_delivery_claims_nothing(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    assert rig.events(rig.slack.forge(raw))[0] == 401
    assert rig.events(raw)[0] == 200
    assert len(rig.queue.items) == 1


# --- failures -----------------------------------------------------------------------------------


def test_a_queue_failure_is_503_so_slack_retries_and_the_retry_is_not_dropped(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    original = rig.queue.enqueue

    def boom(n: Nudge) -> None:
        raise RuntimeError("down")

    rig.queue.enqueue = boom  # type: ignore[method-assign,assignment]
    assert rig.events(raw)[0] == 503
    rig.queue.enqueue = original  # type: ignore[method-assign]
    assert rig.events(rig.slack.retry(raw, 1))[0] == 200
    assert len(rig.queue.items) == 1


# --- the budget ---------------------------------------------------------------------------------


def test_handler_has_no_heavy_imports_and_imports_inside_the_budget() -> None:
    code = (
        "import sys, time\n"
        "t = time.perf_counter()\n"
        "import sto.ingest.slack\n"
        "dt = time.perf_counter() - t\n"
        "heavy = ('boto3', 'botocore', 'pydantic', 'httpx', 'requests', 'urllib3', 'slack_sdk',\n"
        "         'sqlalchemy', 'numpy', 'sto.engine', 'sto.adapters', 'sto.gates')\n"
        "bad = sorted(m for m in sys.modules if m.split('.')[0] in heavy\n"
        "             or any(m == h or m.startswith(h + '.') for h in heavy))\n"
        "print(repr(bad), dt)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=30
    ).stdout.split()
    assert out[0] == "[]", out
    assert float(out[1]) < 1.0


def test_ack_path_completes_inside_one_second_measured(rig: Rig) -> None:
    raws = [rig.slack.event("app_mention") for _ in range(20)]
    raws += [rig.slack.block_actions("approve") for _ in range(20)]
    worst = 0.0
    for raw in raws:
        start = time.perf_counter()
        if raw.headers["Content-Type"] == "application/json":
            status = rig.ingest.events(raw.headers, raw.body).status
        else:
            status = rig.ingest.interactivity(raw.headers, raw.body).status
        worst = max(worst, time.perf_counter() - start)
        assert status == 200
    assert worst < 1.0
