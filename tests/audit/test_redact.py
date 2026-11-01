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
        "jwt: see the RFC",
    ],
)
def test_ordinary_prose_is_not_over_redacted(text: str) -> None:
    assert redact_text(text) == text


def test_text_around_a_removed_pair_is_kept() -> None:
    assert redact_text("before password=hunter2hunter2 after") == (
        f"before password={REDACTED} after"
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
        "  'xeyJaaaa' * 40000, 'eyJaaaaa.bbbbb-' * 25000, 'password=' + chr(92) * 400000,\n"
        "  ('password=' + chr(92) * 3 + chr(34)) * 20000, 'token' + chr(92) * 400000,\n"
        "  'Bearer%20' * 40000, 'password%3D' * 40000,\n"
        "  'https://' * 40000, 'redis://:' * 40000, 'cookie=' * 50000, 'secret' + ' ' * 100000,\n"
        "  (chr(92) + chr(34)) * 100000, ('password=' + chr(92) + chr(34)) * 40000,\n"
        "  'a' * 800000, 'password' * 100000, 'password: ' * 60000]\n"
        "keys = {'ghp_%030d' % i: i for i in range(20000)}\n"
        "t = time.perf_counter(); r.redact(keys)\n"
        "worst = time.perf_counter() - t\n"
        "for s in shapes:\n"
        "    t = time.perf_counter(); r.redact_text(s)\n"
        "    worst = max(worst, time.perf_counter() - t)\n"
        "print(worst)\n"
    )
    try:
        done = subprocess.run(
            [sys.executable, "-I", "-c", code],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("redaction did not finish its hostile shapes in 30 s: a pattern is not linear")
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


# --- pass 3 -------------------------------------------------------------------------------------

JWT2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlX2hlcmU"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Token abc123def456abc123", "abc123def456"),
        ("Authorization: ApiKey abc123def456abc123", "abc123def456"),
        ("Authorization: Digest username=bob, response=abc123def456", "abc123def456"),
        ("Authorization: Basic abc123", "abc123"),
        ('{"Authorization": "Token abc123def456abc123"}', "abc123def456"),
        ('{\\"Authorization\\": \\"Token abc123def456abc123\\"}', "abc123def456"),
        ("Authorization%3A%20Bearer%20abc123def456", "abc123def456"),
        ('{"Cookie": "sid=abc123def456"}', "abc123def456"),
        ('{"cookie":"sid=abc123def456"}', "abc123def456"),
        ("cookie=sid123456789", "sid123456"),
        ("Cookie: abc123def456", "abc123def456"),
        ("redis://:hunter2hunter2@host:6379", "hunter2"),
        ("https://hunter2hunter2@host/x", "hunter2"),
        ("postgres://me@corp.com:hunter2hunter2@host/db", "hunter2"),
        ("https://u:pa/ss1234567@host", "ss1234567"),
        ("s3://AKIAkeyname:hunter2hunter2@bucket", "hunter2"),
        ("secrets=abc123def456", "abc123def456"),
        ("passwords: hunter2hunter2", "hunter2"),
        ('{"passwords":["hunter2hunter2"]}', "hunter2"),
        ("pass=hunter2hunter2", "hunter2"),
        ('"pass": "hunter2hunter2"', "hunter2"),
        ("api key: abc123def456", "abc123def456"),
        ("password=abc,defghi123", "defghi123"),
        ("password=abc;defghi123", "defghi123"),
        ("password=it'ssecret123", "ssecret123"),
        ("password=pass}word123", "word123"),
        ('password="abc\\"defghi123"', "defghi123"),
        ("password = 'abc\\'defghi123'", "defghi123"),
        ("password='single quoted words'", "quoted words"),
        ("password='unterminated single words", "single words"),
        ("passphrase=correcthorsebattery", "correcthorse"),
        ("pwd=correcthorsebattery", "correcthorse"),
        ("passwd=correcthorsebattery", "correcthorse"),
        ("credentials=correcthorsebattery", "correcthorse"),
        ("credential: correcthorsebattery", "correcthorse"),
        ("private_key=correcthorsebattery", "correcthorse"),
        ("private-key: correcthorsebattery", "correcthorse"),
        ("password%3Dhunter2hunter2", "hunter2"),
        ("token%3Ahunter2hunter2", "hunter2"),
        (
            "-----BEGIN PRIVATE KEY BLOCK-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY BLOCK-----",
            "MIIEvQ",
        ),
        ("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIEvQIBADANBgkq", "MIIEvQ"),
        ("xapp-1-A012-abc123def456", "abc123def456"),
        ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "AIzaSyA1"),
        ("npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm_abc"),
        ("hf_abcdefghijklmnopqrstuvwxyz012345", "hf_abc"),
        ("pypi-AgEIcHlwaS5vcmcCabc123456789012345", "AgEIcHlw"),
    ],
)
def test_pass_3_shapes_are_removed(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out
    assert REDACTED in out
    assert redact_text(out) == out


@pytest.mark.parametrize(
    "text",
    [
        "x" + JWT2,
        "token_" + JWT2,
        "id-" + JWT2,
        "Bearer%20" + JWT2,
        "access_token%3D" + JWT2,
        "next=%2Fcb%3Faccess_token%3D" + JWT2 + "%26x%3D1",
        "s%3A" + JWT2,
        JWT2 + "." + JWT2,
    ],
)
def test_glued_and_encoded_jwts_are_removed(text: str) -> None:
    out = redact_text(text)
    assert JWT2[:20] not in out
    assert "c2lnbmF0dXJlX2hlcmU" not in out


def test_prose_after_token_colon_is_redacted_by_decision() -> None:
    """A word after ``token:`` is taken for a value. Pinned so a change is deliberate."""
    assert redact_text("the token: looks wrong") == f"the token: {REDACTED} wrong"


def test_the_ordinary_url_and_time_shapes_are_left_alone() -> None:
    for text in [
        "https://github.com/o/r/pull/285",
        "https://github.com/o/r@v1.2",
        "http://localhost:8080/x",
        "https://github.com:443/org/repo@main",
        "email me: a@b.com at 10:30",
        "time: 12:30:45",
        "user:pass@host",
        "a basic approach to this",
    ]:
        assert redact_text(text) == text, text


def test_pass_is_a_secret_only_with_an_equals_sign_or_as_a_quoted_key() -> None:
    assert redact_text("pass: through the gate") == "pass: through the gate"
    assert redact_text("a bypass=enabled flag") == "a bypass=enabled flag"
    assert redact_text("compass=northeast") == "compass=northeast"


def test_a_certificate_block_is_not_a_private_key_but_the_key_after_it_is() -> None:
    text = "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n"
    key = "-----BEGIN PRIVATE KEY-----\nMIIBkey\n-----END PRIVATE KEY-----"
    assert redact_text(text) == text
    assert redact_text(text + key) == text + REDACTED


@pytest.mark.parametrize(
    "name",
    [
        "APIToken", "AWSSecret", "JWTSecret", "APISecret", "accesstoken", "apitoken", "authtoken",
        "sessiontoken", "refreshtoken", "clientsecret", "client_secret", "privatekey",
        "private_key",
        "secretkey", "sshkey", "SSHKey", "password1", "password_old", "token2", "token_value",
        "secret_value", "pass", "Pass", "passwd", "pwd", "signing_key", "signingKey",
        "encryption_key", "access_key", "apiKey", "api_key", "secret_new", "password_current",
        "APIPass", "DBPwd", "AWSAuth",
    ],
)  # fmt: skip
def test_secret_names_match_at_the_end_of_the_normalised_name(name: str) -> None:
    assert redact({name: "hunter2hunter2"}) == {name: REDACTED}


@pytest.mark.parametrize(
    "name",
    [
        "tokens_used", "token_budget", "secret_ref", "tokens", "token_count", "max_tokens",
        "foo_key", "key", "monkey", "bypass", "compass", "passthrough", "authorized",
        "auth_method", "cookie_policy", "password_changed_at", "subject_digest", "decision",
    ],
)  # fmt: skip
def test_names_that_are_not_secrets_are_kept(name: str) -> None:
    assert redact({name: "keepme"}) == {name: "keepme"}


def test_redacted_key_collisions_get_a_counter_not_a_search() -> None:
    out = redact({f"ghp_{i:030d}": i for i in range(50)})
    assert len(out) == 50
    assert sorted(out.values()) == list(range(50))
    assert REDACTED in out
    assert f"{REDACTED}#1" in out
    assert f"{REDACTED}#49" in out


def test_a_real_key_that_looks_like_a_counter_does_not_lose_a_value() -> None:
    out = redact({f"{REDACTED}#1": 3, "ghp_" + "a" * 30: 1, "ghp_" + "b" * 30: 2})
    assert sorted(out.values()) == [1, 2, 3]


# --- pass 4 -------------------------------------------------------------------------------------

W = "Zq9xW7kP2mR4vT"


@pytest.mark.parametrize(
    "text",
    [
        f'Authorization: Digest username="bob", response="{W}"',
        f'Authorization: Bearer abc"{W}',
        f"Authorization: Bearer abc'{W}",
        f"Authorization: Bearer abc&{W}",
        f"Cookie: a=b'{W}",
        f'Cookie: a="b"; sid={W}',
    ],
)
def test_an_unquoted_header_value_runs_to_the_end_of_the_line(text: str) -> None:
    assert W not in redact_text(text)
    assert W[:8] not in redact_text(text)


def test_a_quoted_header_value_stops_at_its_own_closing_quote() -> None:
    out = redact_text(f'{{"Authorization": "Token {W}", "keep": "this"}}')
    assert W not in out
    assert '"keep": "this"' in out


@pytest.mark.parametrize(
    "text",
    [
        f"password1={W}",
        f"PASSWORD2={W}",
        f"password_old={W}",
        f"DB_PASSWORD_1={W}",
        f"token2={W}",
        f"token_value={W}",
        f"secret_value={W}",
        f"API_KEY_2={W}",
        f"apikey1={W}",
        f"GITHUB_TOKEN_OLD={W}",
        f"signing_key={W}",
        f"encryption_key={W}",
        f"ssh_key={W}",
        f"sshkey: {W}",
        f"HTTP_AUTHORIZATION=Token {W}",
        f"HTTP_COOKIE=sid={W}",
        f"session_cookie={W}",
        f"MY_AUTH={W}1",
        f"BASIC_AUTH=user:{W}1",
        f"my_jwt={W}123",
        f"password := {W}",
        f'password := "{W}"',
        f"password => {W}",
        f'"password" => "{W}"',
        f":password => '{W}'",
        f"--password {W}",
        f"--token {W}",
        f"mysql -u root --password {W}",
        f"--password_old {W}",
        f"<password>{W}</password>",
        f"<token>{W}</token>",
        f"<API_KEY_2>{W}</API_KEY_2>",
        f"https://x/?sig={W}",
        f"https://x/?a=1&signature={W}&b=2",
        f"X-Amz-Signature={W}",
        f"https://x/?X-Amz-Signature={W}&X-Amz-Expires=60",
    ],
)
def test_names_in_text_agree_with_the_names_in_dict_keys(text: str) -> None:
    out = redact_text(text)
    assert W not in out
    assert W[:8] not in out
    assert redact_text(out) == out


@pytest.mark.parametrize(
    "text",
    [
        "pass --verbose to the script",
        "see <token> for details",
        "token_budget=100000 and tokens_used=500",
        "https://x/?page=2&sort=asc",
        "a signature line, sig for short",
    ],
)
def test_the_new_shapes_leave_prose_alone(text: str) -> None:
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "prefix", ["x_", "url_", "a" * 30, "foo.bar.baz.qux.quux.corge.example.com.", "(", "`"]
)
def test_url_credentials_are_found_after_any_prefix(prefix: str) -> None:
    for scheme in ("https", "postgres", "s3", "a1"):
        out = redact_text(f"{prefix}{scheme}://u:{W}@h")
        assert W not in out, (prefix, scheme)


def test_the_three_level_json_form_is_caught() -> None:
    for levels in (1, 2, 3):
        bs = "\\" * levels
        text = bs + '"password' + bs + '": ' + bs + '"' + W + bs + '"'
        out = redact_text(text)
        assert W not in out, levels


def test_url_passwords_over_300_characters_are_a_stated_limit() -> None:
    long_pw = "p" * 400
    assert long_pw in redact_text(f"https://u:{long_pw}@h")  # stated in the module docstring
    assert "p" * 250 not in redact_text(f"https://u:{'p' * 250}@h")
    assert "p" * 250 not in redact_text(f"https://{'p' * 250}@h")  # no colon: the other form
    assert "p" * 350 in redact_text(f"https://{'p' * 350}@h")


@pytest.mark.parametrize(
    "name", ["auth_header", "authorization_header", "Authorization-Header", "private_key_pem"]
)
def test_header_and_pem_names_are_secret_names(name: str) -> None:
    assert redact({name: W}) == {name: REDACTED}


@pytest.mark.parametrize("name", ["oauth", "Oauth", "OAuth_provider", "token_hash", "author"])
def test_names_that_only_look_like_secrets_are_kept(name: str) -> None:
    assert redact({name: "keepme"}) == {name: "keepme"}


def test_a_token_value_that_is_a_number_becomes_a_string_by_design() -> None:
    assert redact({"token": 5}) == {"token": REDACTED}


def test_second_pass_changes_a_password_with_slash_and_at_by_design() -> None:
    once = redact_text("https://u:ab/cd@X@h")
    assert once != redact_text(once)  # the docstring says idempotence is not a guarantee


def test_collisions_that_run_into_two_planted_levels_lose_nothing() -> None:
    planted = {f"{REDACTED}#1": "a", f"{REDACTED}#1#1": "b"}
    keys = {f"ghp_{c * 30}": c for c in "xyz"}
    out = redact({**planted, **keys})
    assert sorted(out.values()) == ["a", "b", "x", "y", "z"]
    assert len(out) == 5


def test_a_word_after_dash_dash_password_is_taken_for_its_value_by_decision() -> None:
    assert redact_text("the --password flag is documented") == (
        f"the --password {REDACTED} is documented"
    )
