"""Secrets are removed before anything is stored; comment text is kept (PLAN 4.9)."""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from audit.helpers import RUN, TEAM, Recorder, audit_items, template_run
from sto.audit.redact import REDACTED, redact, redact_text
from sto.audit.verify import verify_run
from sto.gates.hooks import AuditEntry, ChainedAuditWriter
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import Put

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
SLACK = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"
PAT = "github_pat_" + "11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789"
SK = "sk-" + "mallorymallorymallorymallory"
GL = "glpat-" + "abcdefghijklmnopqrst"
RK = "rk_live_" + "abcdefghijklmnopqrstuvwx"
STRIPE = "sk_live_" + "abcdefghijklmnopqrstuvwx"
ASIA = "ASIA" + "ABCDEFGHIJKLMNOP"


@pytest.mark.parametrize(
    "secret",
    [GH, AWS, ASIA, SLACK, JWT, PEM, PAT, SK, GL, STRIPE, RK],
    ids=[
        "ghp",
        "AKIA",
        "ASIA",
        "slack",
        "jwt",
        "pem",
        "github_pat",
        "sk-",
        "glpat",
        "stripe",
        "rk",
    ],
)
def test_token_shapes_are_removed_from_free_text(secret: str) -> None:
    out = redact({"comment": f"see {secret} for details"})
    assert secret not in str(out)
    assert out["comment"] == f"see {REDACTED} for details"


@pytest.mark.parametrize(
    "text",
    [
        "GITHUB_TOKEN=abcdef123456",
        "DB_PASSWORD=hunter2hunter2",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
        "access_token=abcdef123456",
        "x-api-key: abcdef123456",
        'password="hunter2hunter2"',
        'password="two words here"',
        '{"password": "hunter2hunter2"}',
        "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==",
        "Authorization: Bearer abcdef0123456789xyz",
        "https://bob:hunter2hunter2@github.com/x/y",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkq",
        "sessionToken: abcdef123456",
        "Cookie: sid=abc123def456; theme=dark",
        "Set-Cookie: session=abc123def456; Path=/",
        "Authorization: abc123def456ghi",
        "authorization=Bearer abcdefghijkl",
        "auth=abc123def456",
        "jwt: abc123def456",
        'password="unterminated words here',
        '{\\"password\\": \\"hunter2hunter2\\"}',
        "see Bearer abcdef0123456789xyz here",
    ],
)
def test_assignments_headers_urls_and_unterminated_keys_are_removed(text: str) -> None:
    out = redact_text(text)
    for word in ("hunter2", "abcdef", "dXNlcjpw", "wJalrXU", "MIIEvQ", "two words"):
        assert word not in out
    assert REDACTED in out


@pytest.mark.parametrize(
    "text",
    [
        "a basic approach to this",
        "basic authentication is enough here",
        "Basic usage of the tool",
        "a bearer of good news",
        "bearer authentication works",
        "auth: failed twice",
        "the cookie: chocolate chip",
        "authorization: pending",
        "jwt: see the RFC",
    ],
)
def test_ordinary_prose_is_not_over_redacted(text: str) -> None:
    assert redact_text(text) == text


def test_text_around_a_removed_pair_is_kept() -> None:
    assert redact_text("before password=hunter2hunter2, after") == (
        f"before password={REDACTED}, after"
    )
    assert redact_text("see https://bob:pw12345@h.io/x now") == f"see https://{REDACTED}@h.io/x now"
    assert redact_text("a\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nb") == (
        f"a\n{REDACTED}\nb"
    )


@pytest.mark.parametrize(
    "name",
    [
        "token", "access_token", "password", "secret", "api_key", "Authorization", "private_key",
        "sessionToken", "refreshToken", "authToken", "secretKey", "mySecret", "passphrase",
        "DB_PASSWORD", "secrets", "client_secret", "cookie",
    ],
)  # fmt: skip
def test_values_under_secret_names_are_removed_whatever_they_look_like(name: str) -> None:
    out = redact({"outer": [{name: "plain-looking-value", "kept": "plain-looking-value"}]})
    assert out["outer"][0][name] == REDACTED
    assert out["outer"][0]["kept"] == "plain-looking-value"


@pytest.mark.parametrize(
    "name", ["tokens_used", "token_budget", "secret_ref", "password_changed_at", "cookie_consent"]
)
def test_names_that_hold_numbers_and_references_are_kept(name: str) -> None:
    assert redact({name: "V"}) == {name: "V"}
    assert redact_text(f"{name}=12345 and {name}: 67890") == f"{name}=12345 and {name}: 67890"


def test_a_secret_used_as_a_dict_key_is_removed_and_two_do_not_collide() -> None:
    out = redact({GH: 1, AWS: 2, "a": {GH: {"b": GH}}})
    assert GH not in str(out)
    assert AWS not in str(out)
    assert sorted(v for k, v in out.items() if k != "a") == [1, 2]


def test_tuples_and_other_mappings_are_walked() -> None:
    out = redact({"c": (f"x {GH}", {"token": "t"})})
    assert out == {"c": [f"x {REDACTED}", {"token": REDACTED}]}
    assert redact(types.MappingProxyType({"token": "x"})) == {"token": REDACTED}


def test_comment_text_and_other_values_are_kept() -> None:
    data = {"comment": "LGTM, but please rename foo to bar. Ticket SWE-12.", "round": 2, "ok": True}
    assert redact(data) == data


def test_redact_does_not_mutate_and_is_idempotent() -> None:
    data = {"a": {"b": [f"x {GH} password=hunter2hunter2 {PEM}"]}}
    once = redact(data)
    assert GH in data["a"]["b"][0]
    assert redact(once) == once


def test_redaction_is_linear_on_hostile_input() -> None:
    """Each shape took seconds to minutes with a backtracking pattern. Run in a child process
    under a hard timeout, so a regression fails here instead of hanging the suite. The child
    puts this checkout's ``src`` first on its path and checks that is the ``sto`` it imported
    (``-I`` ignores ``PYTHONPATH``, so the path is set in the code)."""
    src = str(Path(__file__).resolve().parents[2] / "src")
    code = (
        "import sys, time\n"
        f"sys.path.insert(0, {src!r})\n"
        "import sto.audit.redact as r\n"
        f"assert r.__file__.startswith({src!r}), r.__file__\n"
        "shapes = ['-----BEGIN PRIVATE KEY-----' * 14000, '-----BEGIN ' + 'A ' * 200000,\n"
        "  'bearer ' * 60000, 'token=' * 60000, 'ghp_' * 80000, 'eyJaaaaa.' * 40000,\n"
        "  'eyJaaaaa-' * 40000, 'eyJ' * 100000, 'eyJaaaaa_' * 40000, 'sk-' * 100000,\n"
        "  'glpat-a ' * 50000, 'a://x:' * 50000, 'bearer' + ' ' * 1000 * 100,\n"
        "  'token' + ' ' * 1000 * 100, 'token=\"' * 50000, \"token='a\\\" \" * 30000,\n"
        "  'password\\\\\": ' * 30000, 'cookie:' * 50000, 'Cookie: ' + 'a' * 400000,\n"
        "  'authorization: ' * 30000, 'auth=' * 60000, 'jwt:' * 60000, 'basic ' * 60000,\n"
        "  'a' * 800000, 'password' * 100000, 'password: ' * 60000]\n"
        "worst = 0.0\n"
        "for s in shapes:\n"
        "    t = time.perf_counter(); r.redact_text(s)\n"
        "    worst = max(worst, time.perf_counter() - t)\n"
        "print(worst)\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=120, check=True
    )
    assert float(done.stdout) < 5.0


# --- the writer ---------------------------------------------------------------------------------


def _entry(**kw: Any) -> AuditEntry:
    base = {"run_id": RUN, "action": "gate.decided", "actor": "alice", "data": {}, "at": 1}
    return AuditEntry(**{**base, **kw})


def _stored(entry: AuditEntry) -> dict[str, Any]:
    first = next(iter(ChainedAuditWriter().ops(MemoryStore(), TEAM, entry)))
    assert isinstance(first, Put)
    return dict(first.data)


def test_the_default_writer_redacts_data_and_action_but_not_the_actor() -> None:
    body = _stored(_entry(action=f"x {GH}", actor=SK, data={"comment": f"t {GH}", "token": "v"}))
    assert GH not in str(body)
    assert body["data"] == {"comment": f"t {REDACTED}", "token": REDACTED}
    assert body["action"] == f"x {REDACTED}"
    assert body["actor"] == SK  # a launderer's name must stay visible


def test_a_secret_in_a_comment_is_not_in_the_chain_and_the_hash_covers_the_stored_form() -> None:
    store = Recorder()
    service = GateService(store)  # the default writer, nothing opted in
    template_run(service, RUN, comment=f"my token is {GH} and {AWS}")
    blob = str(audit_items(store.inner, RUN))
    assert GH not in blob
    assert AWS not in blob
    assert REDACTED in blob
    assert verify_run(store.inner, TEAM, RUN) == len(audit_items(store.inner, RUN))


@pytest.mark.parametrize("secret", [GH, AWS, PAT, GL, STRIPE, SLACK], ids=lambda s: s[:6])
def test_provider_tokens_are_removed_even_glued_to_a_word_character(secret: str) -> None:
    out = redact_text(f"x{secret}y and token{secret}")
    assert secret not in out
    assert secret[8:] not in out


def test_a_long_digitless_bearer_value_is_a_credential_but_a_short_word_is_prose() -> None:
    assert redact_text("Bearer abcdefghijklmnopqrstuv") == f"Bearer {REDACTED}"
    assert redact_text("bearer authentication") == "bearer authentication"


def test_a_url_password_with_an_at_sign_is_removed_whole() -> None:
    assert redact_text("https://bob:p@ssw0rd@github.com/x") == f"https://{REDACTED}@github.com/x"


def test_tokens_alone_is_a_count_but_secrets_and_passwords_are_secret() -> None:
    assert redact({"tokens": 1200, "secrets": "a", "passwords": "b"}) == {
        "tokens": 1200,
        "secrets": REDACTED,
        "passwords": REDACTED,
    }
