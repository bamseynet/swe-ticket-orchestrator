"""Secrets are removed before anything is stored; comment text is kept (PLAN 4.9)."""

from __future__ import annotations

import pytest

from audit.helpers import RUN, TEAM, Recorder, audit_items, template_run
from sto.audit.chain import AuditChainWriter
from sto.audit.redact import REDACTED, redact
from sto.gates.service import GateService

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
SLACK = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"


@pytest.mark.parametrize("secret", [GH, AWS, SLACK, JWT, PEM])
def test_token_shapes_are_removed_from_free_text(secret: str) -> None:
    out = redact({"comment": f"see {secret} for details"})
    assert secret not in str(out)
    assert REDACTED in out["comment"]
    assert out["comment"].startswith("see ")
    assert out["comment"].endswith(" for details")


def test_bearer_header_and_assignments_are_removed() -> None:
    out = redact({"c": "Authorization: Bearer abcdef0123456789xyz and password=hunter2hunter2"})
    assert "abcdef0123456789xyz" not in str(out)
    assert "hunter2hunter2" not in str(out)


@pytest.mark.parametrize(
    "name",
    ["token", "access_token", "password", "secret", "api_key", "Authorization", "private_key"],
)
def test_values_under_secret_names_are_removed_whatever_they_look_like(name: str) -> None:
    out = redact({"outer": [{name: "plain-looking-value", "kept": "plain-looking-value"}]})
    assert out["outer"][0][name] == REDACTED
    assert out["outer"][0]["kept"] == "plain-looking-value"


def test_comment_text_and_other_values_are_kept() -> None:
    data = {"comment": "LGTM, but please rename foo to bar. Ticket SWE-12.", "round": 2, "ok": True}
    assert redact(data) == data


def test_redact_does_not_mutate_and_is_idempotent() -> None:
    data = {"a": {"b": [f"x {GH}"]}}
    once = redact(data)
    assert GH in data["a"]["b"][0]
    assert redact(once) == once


def test_the_writer_stores_the_redacted_form_and_the_hash_covers_it() -> None:
    store = Recorder()
    service = GateService(store, audit=AuditChainWriter())
    template_run(service, comment=f"my token is {GH} and {AWS}")
    blob = str(audit_items(store.inner, RUN))
    assert GH not in blob
    assert AWS not in blob
    assert REDACTED in blob
    from sto.audit.verify import verify_run

    assert verify_run(store.inner, TEAM, RUN) == len(audit_items(store.inner, RUN))
