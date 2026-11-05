"""D6-09: webhook registration (expiry, refresh, the per-app limit) and deliveries (signatures,
retries that keep the identifier, no ordering). Synthetic secrets and payloads."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import pytest

from fakes.jira.issues import BASIC
from fakes.jira.workflow import (
    ADMIN_SECRET,
    CLIENT_SECRET,
    FakeJiraWebhooks,
    FakeJiraWorkflow,
)
from sto.adapters.ports import RawWebhook

API = "/rest/api/3"
DAY = 86_400.0


@pytest.fixture
def jira() -> FakeJiraWorkflow:
    return FakeJiraWorkflow()


@pytest.fixture
def hooks(jira: FakeJiraWorkflow) -> FakeJiraWebhooks:
    return FakeJiraWebhooks(jira)


def register(jira: FakeJiraWorkflow, jql: str = "project = SYN", **extra: Any) -> Any:
    body = {
        "url": "https://receiver.example.test/hook",
        "webhooks": [{"events": ["jira:issue_updated"], "jqlFilter": jql, **extra}],
    }
    return jira.request("POST", f"{API}/webhook", auth=jira.new_bearer(), json=body)


def ok(r: Any) -> int:
    assert r.status == 200, r.body
    (result,) = r.body["webhookRegistrationResult"]
    assert "errors" not in result, result
    return int(result["createdWebhookId"])


# --- registration ---------------------------------------------------------------------------


def test_registration_needs_an_oauth_or_connect_app(jira: FakeJiraWorkflow) -> None:
    body = {
        "url": "https://r.example.test/h",
        "webhooks": [{"events": ["x"], "jqlFilter": "project = SYN"}],
    }
    assert jira.request("POST", f"{API}/webhook", auth=BASIC, json=body).status == 403  # API token
    assert jira.request("GET", f"{API}/webhook", auth=BASIC).status == 403
    assert jira.request("POST", f"{API}/webhook", auth=None, json=body).status == 401


def test_register_list_expire_after_30_days(jira: FakeJiraWorkflow) -> None:
    wid = ok(register(jira))
    listed = jira.request("GET", f"{API}/webhook", auth=jira.new_bearer()).body
    (hook,) = listed["values"]
    assert hook["id"] == wid
    assert hook["jqlFilter"] == "project = SYN"
    assert hook["events"] == ["jira:issue_updated"]
    assert hook["expirationDate"] == int((jira.now + 30 * DAY) * 1000)  # epoch milliseconds
    assert listed["isLast"] is True


def test_refresh_extends_by_30_days_from_the_call(jira: FakeJiraWorkflow) -> None:
    wid = ok(register(jira))
    jira.now += 20 * DAY
    r = jira.request(
        "PUT", f"{API}/webhook/refresh", auth=jira.new_bearer(), json={"webhookIds": [wid]}
    )
    assert r.status == 200
    assert r.body == {"expirationDate": int((jira.now + 30 * DAY) * 1000)}
    assert jira.webhook_expiry(wid) == jira.now + 30 * DAY


def test_refresh_ignores_unknown_ids_and_needs_a_list(jira: FakeJiraWorkflow) -> None:
    ok(register(jira))

    def refresh(body: Any) -> Any:
        return jira.request("PUT", f"{API}/webhook/refresh", auth=jira.new_bearer(), json=body)

    assert refresh({"webhookIds": [999]}).status == 200  # spec: unrecognised IDs are ignored
    assert refresh({}).status == 400
    assert refresh({"webhookIds": "1"}).status == 400


def test_limit_is_five_per_app_and_user(jira: FakeJiraWorkflow) -> None:
    ids = [ok(register(jira)) for _ in range(5)]
    sixth = register(jira)
    (result,) = sixth.body["webhookRegistrationResult"]
    assert sixth.status == 200
    assert "createdWebhookId" not in result
    assert result["errors"]
    r = jira.request(
        "DELETE", f"{API}/webhook", auth=jira.new_bearer(), json={"webhookIds": ids[:1]}
    )
    assert r.status == 202
    ok(register(jira))


def test_jql_subset_is_enforced(jira: FakeJiraWorkflow) -> None:
    for good in ("project = SYN", "project in (SYN, OTH) AND status != Done", "issueKey = SYN-1"):
        ok(register(jira, good))
        jira.clear_webhooks()
    for bad in (
        'labels = "agent-ready"',
        "project = SYN ORDER BY created",
        "cf[10050] = 1",
        "summary ~ x",
    ):
        (result,) = register(jira, bad).body["webhookRegistrationResult"]
        assert result["errors"], bad


def test_registration_validates_the_body(jira: FakeJiraWorkflow) -> None:
    for body in (
        {},
        {"url": "u"},
        {"url": "u", "webhooks": []},
        {"url": "u", "webhooks": [{"events": []}]},
    ):
        r = jira.request("POST", f"{API}/webhook", auth=jira.new_bearer(), json=body)
        assert r.status == 400, body


def test_expired_registrations_stay_listed_for_three_months(jira: FakeJiraWorkflow) -> None:
    wid = ok(register(jira))
    jira.now += 31 * DAY
    assert jira.webhook_expired(wid)
    assert len(jira.request("GET", f"{API}/webhook", auth=jira.new_bearer()).body["values"]) == 1
    jira.now += 100 * DAY
    assert jira.request("GET", f"{API}/webhook", auth=jira.new_bearer()).body["values"] == []


# --- deliveries -----------------------------------------------------------------------------


def make(hooks: FakeJiraWebhooks, key: str, **kw: Any) -> RawWebhook:
    return hooks.admin_event(key, **kw)


def test_admin_delivery_is_signed_over_the_raw_body(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="synthétique ✓")["key"]
    d = make(hooks, key)
    mac = hmac.new(ADMIN_SECRET, d.body, hashlib.sha256).hexdigest()
    assert d.headers["X-Hub-Signature"] == f"sha256={mac}"  # method=signature
    body = json.loads(d.body)
    assert body["webhookEvent"] == "jira:issue_updated"
    assert isinstance(body["timestamp"], int)
    assert body["issue"]["key"] == key
    assert "changelog" in body
    assert d.headers["X-Atlassian-Webhook-Identifier"]
    assert "X-Atlassian-Webhook-Retry" not in d.headers  # only on retries


def test_changelog_only_on_issue_updated(jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks) -> None:
    key = jira.add_issue(summary="a")["key"]
    created = json.loads(make(hooks, key, event="jira:issue_created").body)
    assert "changelog" not in created


def test_identifiers_are_unique_per_event(jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks) -> None:
    key = jira.add_issue(summary="a")["key"]
    ids = {make(hooks, key).headers["X-Atlassian-Webhook-Identifier"] for _ in range(20)}
    assert len(ids) == 20


def test_forged_signatures_differ_in_signature_only(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    real = make(hooks, key)
    fake = hooks.forged(real)
    assert fake.body == real.body
    assert fake.headers["X-Hub-Signature"] != real.headers["X-Hub-Signature"]
    assert {k: v for k, v in fake.headers.items() if k != "X-Hub-Signature"} == {
        k: v for k, v in real.headers.items() if k != "X-Hub-Signature"
    }
    assert hooks.tampered(real).headers == real.headers
    assert hooks.tampered(real).body != real.body


def test_bearer_delivery_carries_a_jwt_that_does_not_cover_the_body(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    one, two = hooks.bearer_event(key), hooks.bearer_event(key)
    scheme, _, token = one.headers["Authorization"].partition(" ")
    assert scheme == "Bearer"
    head, claims, sig = token.split(".")
    expect = hmac.new(CLIENT_SECRET, f"{head}.{claims}".encode(), hashlib.sha256).digest()
    assert base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)) == expect
    payload = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
    assert payload["exp"] > payload["iat"]
    assert "qsh" not in payload
    assert "hash" not in payload
    assert "X-Hub-Signature" not in one.headers
    assert one.body != two.body  # different events; the token is the same kind
    assert hooks.tampered(one).headers["Authorization"] == one.headers["Authorization"]


def test_retries_reuse_the_webhook_identifier(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    seen: list[RawWebhook] = []

    def receiver(raw: RawWebhook) -> int:
        seen.append(raw)
        return 503 if len(seen) < 3 else 200

    report = hooks.deliver(receiver, make(hooks, key))
    assert [a.status for a in report.attempts] == [503, 503, 200]
    assert report.delivered
    assert len({r.headers["X-Atlassian-Webhook-Identifier"] for r in seen}) == 1
    assert len({r.body for r in seen}) == 1
    assert "X-Atlassian-Webhook-Retry" not in seen[0].headers
    assert [r.headers["X-Atlassian-Webhook-Retry"] for r in seen[1:]] == ["1", "2"]
    assert report.identifier == seen[0].headers["X-Atlassian-Webhook-Identifier"]


def test_retries_are_five_to_fifteen_minutes_apart(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    report = hooks.deliver(lambda _r: 500, make(hooks, key))
    times = [a.at for a in report.attempts]
    assert len(times) == 6
    assert not report.delivered
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    assert all(300 <= g <= 900 for g in gaps)
    assert len(set(gaps)) > 1
    assert jira.now >= times[-1]  # the shared fake clock moved


@pytest.mark.parametrize("status", [408, 409, 425, 429, 500, 502, 503, 599])
def test_retryable_statuses_retry(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks, status: int
) -> None:
    key = jira.add_issue(summary="a")["key"]
    calls = iter([status, 200])
    assert hooks.deliver(lambda _r: next(calls), make(hooks, key)).delivered


@pytest.mark.parametrize("status", [200, 202, 204, 301, 400, 401, 403, 404, 410, 422])
def test_other_statuses_end_the_delivery(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks, status: int
) -> None:
    key = jira.add_issue(summary="a")["key"]
    report = hooks.deliver(lambda _r: status, make(hooks, key))
    assert len(report.attempts) == 1
    assert report.delivered is (status < 300)


def test_a_timeout_or_dropped_connection_retries(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    state = {"n": 0}

    def flaky(_r: RawWebhook) -> int:
        state["n"] += 1
        if state["n"] == 1:
            raise TimeoutError
        return 200

    report = hooks.deliver(flaky, make(hooks, key))
    assert [a.status for a in report.attempts] == [None, 200]


def test_after_30_minutes_of_failure_only_one_attempt_is_made(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    hooks.deliver(lambda _r: 500, make(hooks, key))  # six failures over well over 30 minutes
    assert hooks.degraded
    again = hooks.deliver(lambda _r: 500, make(hooks, key))
    assert len(again.attempts) == 1
    assert hooks.deliver(lambda _r: 200, make(hooks, key)).delivered
    assert not hooks.degraded  # a success lifts it
    assert len(hooks.deliver(lambda _r: 500, make(hooks, key)).attempts) > 1


def test_deliveries_have_no_order_and_can_repeat(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    events = [make(hooks, key) for _ in range(6)]
    shuffled = hooks.unordered(events, seed=1)
    assert sorted(map(id, shuffled)) == sorted(map(id, events))
    assert shuffled != events
    assert hooks.unordered(events, seed=1) == shuffled  # reproducible
    assert hooks.unordered(events[:1], seed=1) == events[:1]
    twin = hooks.duplicate(events[0])
    assert (
        twin.headers["X-Atlassian-Webhook-Identifier"]
        == events[0].headers["X-Atlassian-Webhook-Identifier"]
    )
    assert twin.body == events[0].body
    assert "X-Atlassian-Webhook-Retry" not in twin.headers


def test_stale_event_carries_the_state_at_send_time(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    key = jira.add_issue(summary="a")["key"]
    early = make(hooks, key)
    jira.force_status(key, "Done")
    late = make(hooks, key)
    assert json.loads(early.body)["issue"]["fields"]["status"]["name"] == "To Do"
    assert json.loads(late.body)["issue"]["fields"]["status"]["name"] == "Done"
    assert json.loads(early.body)["timestamp"] <= json.loads(late.body)["timestamp"]


def test_registered_webhooks_deliver_only_while_live_and_matching(
    jira: FakeJiraWorkflow, hooks: FakeJiraWebhooks
) -> None:
    syn = jira.add_issue(summary="a", project="SYN")["key"]
    oth = jira.add_issue(summary="b", project="OTH")["key"]
    wid = ok(register(jira, "project = SYN"))
    got = hooks.registered_events("jira:issue_updated", syn)
    assert len(got) == 1
    assert json.loads(got[0].body)["matchedWebhookIds"] == [wid]
    assert "Authorization" in got[0].headers
    assert hooks.registered_events("jira:issue_updated", oth) == []  # the filter
    assert hooks.registered_events("jira:issue_created", syn) == []  # the event list
    jira.now += 31 * DAY
    assert hooks.registered_events("jira:issue_updated", syn) == []  # expired: silence
    jira.request(
        "PUT", f"{API}/webhook/refresh", auth=jira.new_bearer(), json={"webhookIds": [wid]}
    )
    assert len(hooks.registered_events("jira:issue_updated", syn)) == 1
