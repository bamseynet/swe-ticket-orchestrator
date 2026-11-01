"""OIDC validation: every refusal, key rotation, the Cognito config, and the D12 test plan."""

from __future__ import annotations

import base64
import json

import pytest

from sto.domain.errors import PermanentError, TransientError
from sto.identity.fake_issuer import FakeIssuer
from sto.identity.oidc import (
    D12_TEST_PLAN,
    CachedJwks,
    InvalidTokenError,
    OidcConfig,
    OidcValidator,
    StaticJwks,
    cognito_config,
)

ISS = "https://idp.example.test"
AUD = "sto-client"
NOW = 1_800_000_000.0


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _config(**kw: object) -> OidcConfig:
    return OidcConfig(issuer=ISS, audience=AUD, **kw)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def issuer() -> FakeIssuer:
    return FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)


@pytest.fixture(scope="module")
def other() -> FakeIssuer:
    return FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)  # same kid, different key


def _validator(issuer: FakeIssuer, **kw: object) -> OidcValidator:
    return OidcValidator(_config(**kw), StaticJwks(issuer.jwks()), clock=lambda: NOW)


def _refused(validator: OidcValidator, token: str, reason: str) -> None:
    with pytest.raises(InvalidTokenError) as info:
        validator.validate(token)
    assert info.value.reason == reason
    assert isinstance(info.value, PermanentError)


def test_valid_token_yields_claims(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, groups=["g-1", "g-2"], auth_time=NOW - 30)
    got = _validator(issuer).validate(token)
    assert got.subject == "u1"
    assert got.issuer == ISS
    assert got.groups == ("g-1", "g-2")
    assert got.auth_time == NOW - 30
    assert got.claims["sub"] == "u1"


def test_bad_signature_refused(issuer: FakeIssuer, other: FakeIssuer) -> None:
    token = other.issue(sub="u1", audience=AUD)
    _refused(_validator(issuer), token, "bad_signature")


def test_tampered_payload_refused(issuer: FakeIssuer) -> None:
    head, _, sig = issuer.issue(sub="u1", audience=AUD).split(".")
    forged = _b64(json.dumps({"iss": ISS, "aud": AUD, "sub": "admin", "exp": NOW + 99}).encode())
    _refused(_validator(issuer), f"{head}.{forged}.{sig}", "bad_signature")


def test_wrong_audience_refused(issuer: FakeIssuer) -> None:
    _refused(_validator(issuer), issuer.issue(sub="u1", audience="someone-else"), "bad_audience")


def test_audience_list_containing_ours_accepted(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=["x", AUD])
    assert _validator(issuer).validate(token).subject == "u1"


def test_missing_audience_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, drop=["aud"])
    _refused(_validator(issuer), token, "bad_audience")


def test_expired_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, expires_in=-120)
    _refused(_validator(issuer), token, "expired")


def test_expiry_within_leeway_accepted(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, expires_in=-10)
    assert _validator(issuer, leeway_seconds=60).validate(token).subject == "u1"


def test_missing_expiry_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, drop=["exp"])
    _refused(_validator(issuer), token, "missing_claim")


def test_not_yet_valid_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, extra={"nbf": NOW + 600})
    _refused(_validator(issuer), token, "not_yet_valid")


def test_wrong_issuer_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, issuer_claim="https://evil.example.test")
    _refused(_validator(issuer), token, "bad_issuer")


def test_issuer_prefix_not_accepted(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, issuer_claim=ISS + "/extra")
    _refused(_validator(issuer), token, "bad_issuer")


def test_missing_subject_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, drop=["sub"])
    _refused(_validator(issuer), token, "missing_claim")


def test_alg_none_refused(issuer: FakeIssuer) -> None:
    head = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": "k1"}).encode())
    body = _b64(json.dumps({"iss": ISS, "aud": AUD, "sub": "u", "exp": NOW + 99}).encode())
    _refused(_validator(issuer), f"{head}.{body}.", "bad_algorithm")


def test_hmac_with_public_key_confusion_refused(issuer: FakeIssuer) -> None:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = _b64(json.dumps({"iss": ISS, "aud": AUD, "sub": "u", "exp": NOW + 99}).encode())
    _refused(_validator(issuer), f"{head}.{body}.{_b64(b'x' * 32)}", "bad_algorithm")


def test_crit_header_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, header={"crit": ["exp"]})
    _refused(_validator(issuer), token, "malformed")


def test_unknown_kid_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, header={"kid": "nope"})
    _refused(_validator(issuer), token, "unknown_key")


def test_missing_kid_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u1", audience=AUD, header={"kid": None})
    _refused(_validator(issuer), token, "unknown_key")


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "!!.@@.##", "e30.e30.", "x" * 5000])
def test_malformed_refused(issuer: FakeIssuer, token: str) -> None:
    with pytest.raises(InvalidTokenError):
        _validator(issuer).validate(token)


def test_non_object_payload_refused(issuer: FakeIssuer) -> None:
    token = issuer.issue_raw(payload=b"[1,2]")
    _refused(_validator(issuer), token, "malformed")


def test_token_use_enforced(issuer: FakeIssuer) -> None:
    v = _validator(issuer, token_use="access")
    _refused(v, issuer.issue(sub="u", audience=AUD, extra={"token_use": "id"}), "bad_token_use")
    ok = issuer.issue(sub="u", audience=AUD, extra={"token_use": "access"})
    assert v.validate(ok).subject == "u"


def test_groups_claim_shapes(issuer: FakeIssuer) -> None:
    v = _validator(issuer)
    as_string = issuer.issue(sub="u", audience=AUD, extra={"groups": "g-1"})
    assert v.validate(as_string).groups == ("g-1",)
    absent = issuer.issue(sub="u", audience=AUD, drop=["groups"])
    assert v.validate(absent).groups == ()
    bad = issuer.issue(sub="u", audience=AUD, extra={"groups": [1, {"a": 2}]})
    _refused(v, bad, "malformed")


def test_cognito_audience_claim_is_config(issuer: FakeIssuer) -> None:
    """Cognito access tokens carry ``client_id`` and no ``aud``; that is a config knob."""
    cfg = cognito_config(region="eu-west-2", user_pool_id="eu-west-2_ABC123", client_id=AUD)
    assert cfg.issuer == "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_ABC123"
    assert cfg.jwks_uri == cfg.issuer + "/.well-known/jwks.json"
    assert cfg.audience_claim == "client_id"
    assert cfg.token_use == "access"
    assert cfg.groups_claim == "cognito:groups"
    fake = FakeIssuer(issuer=cfg.issuer, key_id="c1", clock=lambda: NOW)
    token = fake.issue(
        sub="u", audience=AUD, drop=["aud"], extra={"client_id": AUD, "token_use": "access"}
    )
    got = OidcValidator(cfg, StaticJwks(fake.jwks()), clock=lambda: NOW).validate(token)
    assert got.subject == "u"


def test_cognito_config_validates_inputs() -> None:
    with pytest.raises(ValueError, match="region"):
        cognito_config(region="x/../y", user_pool_id="eu-west-2_A", client_id="c")
    with pytest.raises(ValueError, match="user_pool_id"):
        cognito_config(region="eu-west-2", user_pool_id="a/b", client_id="c")


def test_validator_has_no_vendor_branches() -> None:
    import inspect

    assert "cognito" not in inspect.getsource(OidcValidator).lower()


def test_config_refuses_weak_settings() -> None:
    with pytest.raises(ValueError, match="issuer"):
        OidcConfig(issuer="", audience=AUD)
    with pytest.raises(ValueError, match="https"):
        OidcConfig(issuer="http://idp.example.test", audience=AUD)
    with pytest.raises(ValueError, match="algorithm"):
        OidcConfig(issuer=ISS, audience=AUD, algorithms=("HS256",))
    with pytest.raises(ValueError, match="leeway"):
        OidcConfig(issuer=ISS, audience=AUD, leeway_seconds=-1)


def test_es256_supported() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    v = OidcValidator(_config(algorithms=("ES256",)), StaticJwks(fake.jwks()), clock=lambda: NOW)
    assert v.validate(fake.issue(sub="u", audience=AUD)).subject == "u"
    rsa = FakeIssuer(issuer=ISS, key_id="e1", clock=lambda: NOW)
    _refused(v, rsa.issue(sub="u", audience=AUD), "bad_algorithm")


def test_rsa_key_with_es256_header_refused(issuer: FakeIssuer) -> None:
    v = OidcValidator(
        _config(algorithms=("RS256", "ES256")), StaticJwks(issuer.jwks()), clock=lambda: NOW
    )
    token = issuer.issue(sub="u", audience=AUD, header={"alg": "ES256"})
    _refused(v, token, "bad_signature")


# --- JWKS caching and rotation -------------------------------------------------------------


class Fetch:
    def __init__(self, fake: FakeIssuer) -> None:
        self.fake = fake
        self.calls = 0
        self.fail: Exception | None = None

    def __call__(self, uri: str) -> bytes:
        self.calls += 1
        if self.fail:
            raise self.fail
        return json.dumps(self.fake.jwks()).encode()


def _cached(fetch: Fetch, now: list[float]) -> tuple[OidcValidator, CachedJwks]:
    jwks = CachedJwks(
        "https://idp.example.test/jwks",
        fetch,
        ttl_seconds=300,
        min_refetch_seconds=30,
        clock=lambda: now[0],
    )
    return OidcValidator(_config(), jwks, clock=lambda: NOW), jwks


def test_jwks_cached_then_refetched_after_ttl() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    v, _ = _cached(fetch, now)
    token = fake.issue(sub="u", audience=AUD)
    v.validate(token)
    v.validate(token)
    assert fetch.calls == 1
    now[0] += 301
    v.validate(token)
    assert fetch.calls == 2


def test_rotation_picks_up_new_kid_but_rate_limited() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    v, _ = _cached(fetch, now)
    v.validate(fake.issue(sub="u", audience=AUD))
    fake.rotate("k2")
    now[0] += 31
    assert v.validate(fake.issue(sub="u", audience=AUD)).subject == "u"
    assert fetch.calls == 2
    # an attacker spraying unknown kids cannot make us refetch on every request
    junk = fake.issue(sub="u", audience=AUD, header={"kid": "junk"})
    for _ in range(5):
        _refused(v, junk, "unknown_key")
    assert fetch.calls == 2
    now[0] += 31
    _refused(v, junk, "unknown_key")
    assert fetch.calls == 3


def test_retired_key_refused_after_rotation() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    old = fake.issue(sub="u", audience=AUD)
    fetch, now = Fetch(fake), [1000.0]
    fake.rotate("k2", keep_old=False)
    v, _ = _cached(fetch, now)
    _refused(v, old, "unknown_key")


def test_fetch_failure_is_transient_not_invalid() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    fetch.fail = OSError("down")
    v, _ = _cached(fetch, now)
    with pytest.raises(TransientError):
        v.validate(fake.issue(sub="u", audience=AUD))


def test_stale_keys_used_when_refresh_fails() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    v, _ = _cached(fetch, now)
    token = fake.issue(sub="u", audience=AUD)
    v.validate(token)
    fetch.fail = OSError("down")
    now[0] += 400
    assert v.validate(token).subject == "u"


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"keys": "x"}', b'{"keys": [1]}'])
def test_garbage_jwks_is_transient(body: bytes) -> None:
    jwks = CachedJwks("https://idp.example.test/jwks", lambda _u: body, clock=lambda: 0.0)
    with pytest.raises(TransientError):
        jwks.get("k1")


def test_unusable_jwks_entries_skipped(issuer: FakeIssuer) -> None:
    good = issuer.jwks()["keys"][0]
    doc = {"keys": [{"kty": "oct", "kid": "h", "k": "AAAA"}, {"kty": "RSA", "kid": "bad"}, good]}
    jwks = StaticJwks(doc)
    assert jwks.get("h") is None
    assert jwks.get("bad") is None
    assert jwks.get("k1") is not None


def test_jwks_uri_must_be_https() -> None:
    with pytest.raises(ValueError, match="https"):
        CachedJwks("http://idp.example.test/jwks", lambda _u: b"{}")


# --- D12 test plan -----------------------------------------------------------------------


def test_d12_test_plan_covers_what_only_a_real_idp_proves() -> None:
    text = D12_TEST_PLAN.lower()
    for topic in ("group list size", "step-up", "revocation", "d12-10", "l11"):
        assert topic in text
    assert text.count("\n- ") >= 6  # concrete steps, not just headings


def test_weak_rsa_key_in_jwks_is_ignored() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    nums = rsa.generate_private_key(65537, 1024).public_key().public_numbers()

    def enc(n: int) -> str:
        return _b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))

    weak = {"kty": "RSA", "kid": "weak", "n": enc(nums.n), "e": enc(nums.e)}
    assert StaticJwks({"keys": [weak]}).get("weak") is None


def test_truncated_es256_signature_refused() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    v = OidcValidator(_config(algorithms=("ES256",)), StaticJwks(fake.jwks()), clock=lambda: NOW)
    head, body, sig = fake.issue(sub="u", audience=AUD).split(".")
    short = _b64(base64.urlsafe_b64decode(sig + "==")[:-1])
    _refused(v, f"{head}.{body}.{short}", "bad_signature")
