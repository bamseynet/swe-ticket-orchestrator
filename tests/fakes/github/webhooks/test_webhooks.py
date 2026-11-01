"""D4-16: the fake GitHub's webhook deliveries. Synthetic secret, ids and payloads.

This asserts the SHAPE of what the fake sends. Whether a signature is genuine is decided by the
real verifier, which the conformance suite drives through ``test_conformance.py``; nothing here
verifies a signature, and the fake does not either.
"""

from __future__ import annotations

import json
import re

import pytest

from fakes.github.webhooks import SECRET, WRONG_SECRET, FakeWebhooks, ForgeKind
from fakes.github.webhooks.sender import _sign

SIG = "X-Hub-Signature-256"


@pytest.fixture
def clock() -> list[float]:
    return [1_000.0]


@pytest.fixture
def hooks(clock: list[float]) -> FakeWebhooks:
    return FakeWebhooks(lambda: clock[0])


def test_a_delivery_carries_the_headers_github_sends(hooks: FakeWebhooks) -> None:
    raw = hooks.delivery(3, "00000000-0000-4000-8000-000000000001")
    h = raw.headers
    assert h["X-GitHub-Delivery"] == "00000000-0000-4000-8000-000000000001"
    assert h["X-GitHub-Event"] == "issues"
    assert re.fullmatch(r"sha256=[0-9a-f]{64}", h[SIG])
    assert h["Content-Type"] == "application/json"
    assert h["User-Agent"].startswith("GitHub-Hookshot/")
    assert h["X-GitHub-Hook-ID"].isdigit()
    assert h["X-GitHub-Hook-Installation-Target-Type"] == "integration"
    assert h["X-GitHub-Hook-Installation-Target-ID"].isdigit()


def test_github_signs_no_timestamp_and_sends_none(hooks: FakeWebhooks) -> None:
    names = {k.lower() for k in hooks.delivery(1, "d-1").headers}
    assert not {n for n in names if "time" in n or n == "date"}


def test_the_default_body_is_a_synthetic_issues_event(hooks: FakeWebhooks) -> None:
    body = json.loads(hooks.delivery(4, "d-1").body)
    assert body["action"] == "edited"
    assert body["repository"]["full_name"] == "acme/app"
    assert body["issue"]["number"] == 1
    assert body["issue"]["revision"] == 4
    assert body["installation"]["id"] == 200002


def test_the_event_and_body_can_be_chosen(hooks: FakeWebhooks) -> None:
    raw = hooks.delivery(1, "d-1", event="pull_request", body=b'{"a": 1}')
    assert raw.headers["X-GitHub-Event"] == "pull_request"
    assert raw.body == b'{"a": 1}'


def test_a_body_factory_replaces_the_default() -> None:
    raw = FakeWebhooks(lambda: 0.0, body=lambda rev, did: f'{{"r": {rev}}}'.encode()).delivery(
        7, "x"
    )
    assert raw.body == b'{"r": 7}'


def test_the_same_delivery_signs_the_same_and_another_body_signs_differently(
    hooks: FakeWebhooks,
) -> None:
    a, b = hooks.delivery(1, "d-1"), hooks.delivery(1, "d-1")
    other = hooks.delivery(2, "d-1")
    assert a.headers[SIG] == b.headers[SIG] != other.headers[SIG]


def test_the_signature_does_not_depend_on_the_delivery_id_or_the_clock(
    hooks: FakeWebhooks, clock: list[float]
) -> None:
    a = hooks.delivery(1, "d-1").headers[SIG]
    clock[0] += 99999
    assert hooks.delivery(1, "d-2").headers[SIG] == a


def test_no_delivery_id_means_no_delivery_header(hooks: FakeWebhooks) -> None:
    raw = hooks.without_id(1)
    assert "X-GitHub-Delivery" not in raw.headers
    assert SIG in raw.headers


def test_a_malformed_body_is_signed_like_any_other(hooks: FakeWebhooks) -> None:
    raw = hooks.malformed("d-1")
    assert raw.headers["X-GitHub-Delivery"] == "d-1"
    assert re.fullmatch(r"sha256=[0-9a-f]{64}", raw.headers[SIG])
    with pytest.raises(ValueError, match="Expecting"):
        json.loads(raw.body)


# --- forgeries: only the signature differs, and each kind differs from the rest -----------------


def test_every_forgery_changes_the_signature_and_nothing_else(hooks: FakeWebhooks) -> None:
    genuine = hooks.delivery(1, "d-1")
    for how in ForgeKind:
        forged = hooks.forge(1, "d-1", how)
        assert forged.body == genuine.body, how
        assert {k: v for k, v in forged.headers.items() if k != SIG} == {
            k: v for k, v in genuine.headers.items() if k != SIG
        }, how
        assert forged.headers[SIG] != genuine.headers[SIG], how


def test_forgeries_are_consistent_across_kinds(hooks: FakeWebhooks) -> None:
    genuine = hooks.delivery(1, "d-1").headers[SIG]
    sigs = {how: hooks.forge(1, "d-1", how).headers[SIG] for how in ForgeKind}
    assert len(set(sigs.values())) == len(ForgeKind), "no two kinds alike"
    truncated = sigs[ForgeKind.TRUNCATED_MAC]
    assert genuine.startswith(truncated)
    assert len(truncated) < len(genuine)
    assert sigs[ForgeKind.EMPTY_MAC] == "sha256="
    assert genuine.startswith("sha256=")
    assert sigs[ForgeKind.BLANK_HEADER] == ""
    assert re.fullmatch(r"sha256=[0-9a-f]{64}", sigs[ForgeKind.WRONG_SECRET])
    assert re.fullmatch(r"sha256=[0-9a-f]{64}", sigs[ForgeKind.EMPTY_KEY])


def test_the_default_forgery_is_a_wrong_secret(hooks: FakeWebhooks) -> None:
    assert hooks.forge(1, "d-1") == hooks.forge(1, "d-1", ForgeKind.WRONG_SECRET)


def test_a_forgery_is_not_a_delivery_github_made(hooks: FakeWebhooks) -> None:
    hooks.forge(1, "d-forged")
    assert "d-forged" not in hooks.deliveries
    with pytest.raises(KeyError):
        hooks.redeliver("d-forged")


def test_tampering_changes_the_body_and_keeps_the_signature(hooks: FakeWebhooks) -> None:
    raw = hooks.delivery(1, "d-1")
    tampered = hooks.tamper(raw)
    assert tampered.body != raw.body
    assert tampered.headers == raw.headers


def test_reserialising_keeps_the_content_and_changes_the_bytes(hooks: FakeWebhooks) -> None:
    raw = hooks.delivery(1, "d-1")
    other = hooks.reserialise(raw)
    assert other.body != raw.body
    assert json.loads(other.body) == json.loads(raw.body)
    assert other.headers == raw.headers


def test_the_secret_is_synthetic() -> None:
    assert SECRET.startswith(b"synthetic-")


# --- redelivery: the same delivery, byte for byte, and it never ages out ------------------------


def test_a_redelivery_is_the_same_delivery_id_headers_and_bytes(hooks: FakeWebhooks) -> None:
    first = hooks.delivery(1, "d-1")
    assert hooks.redeliver("d-1") == first


def test_a_redelivery_never_expires(hooks: FakeWebhooks, clock: list[float]) -> None:
    """Real GitHub redelivers for three days. The fake does not expire, so the receiver's seen-ID
    table cannot lean on a lapse (D4-03: dedupe does not expire for GitHub)."""
    first = hooks.delivery(1, "d-1")
    clock[0] += 10.0**10
    assert hooks.redeliver("d-1") == first


def test_the_ledger_lists_every_genuine_delivery_in_order(hooks: FakeWebhooks) -> None:
    hooks.delivery(1, "d-1")
    hooks.delivery(2, "d-2")
    assert list(hooks.deliveries) == ["d-1", "d-2"]


def test_a_delivery_with_no_id_is_not_in_the_ledger(hooks: FakeWebhooks) -> None:
    hooks.without_id(1)
    assert hooks.deliveries == {}


# --- each forgery is made the way its name says (the suite cannot check the secret) ---------------


def test_each_forgery_is_signed_the_way_its_name_says(hooks: FakeWebhooks) -> None:
    body = hooks.delivery(1, "d-1").body
    assert hooks.forge(1, "d-1", ForgeKind.EMPTY_KEY).headers[SIG] == _sign(b"", body)
    assert hooks.forge(1, "d-1", ForgeKind.WRONG_SECRET).headers[SIG] == _sign(WRONG_SECRET, body)
    assert hooks.delivery(1, "d-1").headers[SIG] == _sign(SECRET, body)
    assert WRONG_SECRET != SECRET != b""


def test_the_truncated_forgery_keeps_exactly_eight_hex_digits(hooks: FakeWebhooks) -> None:
    genuine = hooks.delivery(1, "d-1").headers[SIG]
    truncated = hooks.forge(1, "d-1", ForgeKind.TRUNCATED_MAC).headers[SIG]
    assert truncated == genuine[: len("sha256=") + 8]
    assert len(genuine) - len(truncated) == 56


def test_the_secret_it_is_given_is_the_one_it_signs_with(clock: list[float]) -> None:
    ours = FakeWebhooks(lambda: clock[0])
    theirs = FakeWebhooks(lambda: clock[0], secret=b"synthetic-another")
    assert ours.delivery(1, "d-1").headers[SIG] != theirs.delivery(1, "d-1").headers[SIG]
    assert theirs.delivery(1, "d-1").headers[SIG] == _sign(
        b"synthetic-another", ours.delivery(1, "d-1").body
    )


def test_a_body_with_non_ascii_text_is_signed_over_its_utf8_bytes(hooks: FakeWebhooks) -> None:
    raw = hooks.delivery(1, "d-1")
    assert "synthétique ✓".encode() in raw.body
    assert raw.headers[SIG] == _sign(SECRET, raw.body)
    assert hooks.reserialise(raw).body != raw.body  # \u escapes: other bytes, same content
    assert hooks.tamper(raw).body.decode().endswith("}" + " ")
