"""OIDC validation: every refusal, key rotation and outages, and the Cognito config."""

from __future__ import annotations

import base64
import itertools
import json
import threading
import time

import pytest

from sto.domain.errors import PermanentError, TransientError
from sto.identity.fake_issuer import FakeIssuer
from sto.identity.oidc import (
    CachedJwks,
    InvalidTokenError,
    Jwk,
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


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "!!.@@.##", "e30.e30."])
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
    """A key with no ``alg`` of its own still cannot be used under the wrong algorithm."""
    jwks = StaticJwks({"keys": [_jwk(issuer, alg=None)]})
    v = OidcValidator(_config(algorithms=("RS256", "ES256")), jwks, clock=lambda: NOW)
    token = issuer.issue(sub="u", audience=AUD, header={"alg": "ES256"})
    _refused(v, token, "bad_signature")


def test_ec_key_with_rs256_header_refused() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    jwks = StaticJwks({"keys": [_jwk(fake, alg=None)]})
    v = OidcValidator(_config(algorithms=("RS256", "ES256")), jwks, clock=lambda: NOW)
    token = fake.issue(sub="u", audience=AUD, header={"alg": "RS256"})  # real ES256 signature
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


# --- review pass 1 -------------------------------------------------------------------------

URI = "https://idp.example.test/jwks"


def _doc_without(fake: FakeIssuer, *drop: str) -> bytes:
    keys = [k for k in fake.jwks()["keys"] if k["kid"] not in drop]
    return json.dumps({"keys": keys}).encode()


def _jwk(fake: FakeIssuer, **changes: object) -> dict[str, object]:
    jwk: dict[str, object] = dict(fake.jwks()["keys"][0])
    jwk.update(changes)
    return {k: v for k, v in jwk.items() if v is not None}


def _get(doc: dict[str, object] | list[dict[str, object]], kid: str) -> object:
    entries = doc if isinstance(doc, list) else [doc]
    return StaticJwks({"keys": entries}).get(kid)


# 1. stale keys are bounded
def test_stale_keys_refused_past_max_stale_seconds() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    v, _ = _cached(fetch, now)
    token = fake.issue(sub="u", audience=AUD)
    v.validate(token)
    fetch.fail = OSError("down")
    now[0] += 5 * 3600
    assert v.validate(token).subject == "u"  # inside the 6 hour default
    now[0] += 2 * 3600
    with pytest.raises(TransientError):
        v.validate(token)  # a key removed at the IdP is not trusted forever


def test_ten_years_of_outage_does_not_keep_keys() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    v, _ = _cached(fetch, now)
    token = fake.issue(sub="u", audience=AUD)
    v.validate(token)
    fetch.fail = OSError("down")
    now[0] += 10 * 365 * 86400
    with pytest.raises(TransientError):
        v.validate(token)


# 2. non-finite and absurd numbers
@pytest.mark.parametrize("claim", ["exp", "nbf", "auth_time", "iat"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 10**400, True])
def test_non_finite_or_absurd_numbers_refused(
    issuer: FakeIssuer, claim: str, value: object
) -> None:
    token = issuer.issue(sub="u", audience=AUD, extra={claim: value})
    _refused(_validator(issuer), token, "malformed")


def test_1e999_literal_refused(issuer: FakeIssuer) -> None:
    body = b'{"iss":"%s","aud":"%s","sub":"u","exp":1e999}' % (ISS.encode(), AUD.encode())
    _refused(_validator(issuer), issuer.issue_raw(payload=body), "malformed")


def test_future_auth_time_refused(issuer: FakeIssuer) -> None:
    v = _validator(issuer, leeway_seconds=60)
    ok = issuer.issue(sub="u", audience=AUD, auth_time=NOW + 60)
    assert v.validate(ok).auth_time == NOW + 60
    _refused(v, issuer.issue(sub="u", audience=AUD, auth_time=NOW + 61), "bad_auth_time")
    _refused(v, issuer.issue(sub="u", audience=AUD, auth_time=NOW * 100), "bad_auth_time")


def test_future_iat_is_not_checked(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u", audience=AUD, extra={"iat": NOW + 10_000})
    assert _validator(issuer).validate(token).subject == "u"


# 3. deep nesting
def test_deeply_nested_header_is_invalid_not_a_crash(issuer: FakeIssuer) -> None:
    deep = _b64(b"[" * 9997)
    token = f"{deep}.{_b64(b'{}')}."
    assert len(token) < 16 * 1024
    _refused(_validator(issuer), token, "malformed")


def test_deeply_nested_payload_is_invalid_not_a_crash(issuer: FakeIssuer) -> None:
    token = issuer.issue_raw(payload=b'{"a":' + b"[" * 5000 + b"]" * 5000 + b"}")
    assert len(token) < 16 * 1024
    with pytest.raises(InvalidTokenError):
        _validator(issuer).validate(token)


# 4. an outage is never a permanent "invalid token"
def test_unknown_kid_during_outage_is_transient_not_invalid() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    v, _ = _cached(fetch, now)
    v.validate(fake.issue(sub="u", audience=AUD))
    fake.rotate("k2")
    k2_token = fake.issue(sub="u", audience=AUD)
    fetch.fail = OSError("down")
    now[0] += 31
    for step in (0, 1, 400, 4000):  # first try, inside the window, after the TTL, much later
        now[0] += step
        with pytest.raises(TransientError):
            v.validate(k2_token)
    fetch.fail = None
    now[0] += 31
    assert v.validate(k2_token).subject == "u"  # and it recovers


def test_200_with_only_unusable_keys_keeps_the_old_set() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    bodies = [json.dumps(fake.jwks()).encode(), b'{"keys":[{"kty":"oct","kid":"k1","k":"AA"}]}']
    now = [1000.0]
    jwks = CachedJwks(URI, lambda _u: bodies[0], ttl_seconds=300, clock=lambda: now[0])
    v = OidcValidator(_config(), jwks, clock=lambda: NOW)
    token = fake.issue(sub="u", audience=AUD)
    v.validate(token)
    bodies[0] = bodies[1]
    now[0] += 301
    assert v.validate(token).subject == "u"  # old key kept
    junk = fake.issue(sub="u", audience=AUD, header={"kid": "other"})
    with pytest.raises(TransientError):
        v.validate(junk)  # and we know the refresh failed


# 5. cold start is rate limited
def test_cold_start_outage_does_not_fetch_per_request() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    fetch.fail = OSError("down")
    v, _ = _cached(fetch, now)
    token = fake.issue(sub="u", audience=AUD)
    for _ in range(1000):
        with pytest.raises(TransientError):
            v.validate(token)
    assert fetch.calls == 1
    now[0] += 31
    with pytest.raises(TransientError):
        v.validate(token)
    assert fetch.calls == 2


# 7. ordering of concurrent refreshes
def test_slow_older_fetch_cannot_restore_a_revoked_key() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fake.rotate("k2")
    old_doc, new_doc = _doc_without(fake), _doc_without(fake, "k1")
    entered, release, counter = threading.Event(), threading.Event(), itertools.count(1)

    def fetch(_uri: str) -> bytes:
        if next(counter) == 1:
            entered.set()
            assert release.wait(10)
            return old_doc
        return new_doc

    now = [1000.0]
    jwks = CachedJwks(URI, fetch, min_refetch_seconds=30, clock=lambda: now[0])
    slow = threading.Thread(target=lambda: jwks.get("k2"))
    slow.start()
    assert entered.wait(10)
    now[0] += 31
    assert jwks.get("k2") is not None  # the newer fetch commits
    release.set()
    slow.join(10)
    assert jwks.get("k1") is None  # the older response did not bring k1 back


# 8. audience strictness
@pytest.mark.parametrize("aud", [[AUD, 1], [AUD, None], [AUD, ["x"]], {"a": AUD}, 7])
def test_non_string_audience_entries_refused(issuer: FakeIssuer, aud: object) -> None:
    token = issuer.issue(sub="u", audience=AUD, extra={"aud": aud})
    _refused(_validator(issuer), token, "bad_audience")


def test_cognito_client_id_must_be_a_single_string() -> None:
    cfg = cognito_config(region="eu-west-2", user_pool_id="eu-west-2_ABC123", client_id=AUD)
    fake = FakeIssuer(issuer=cfg.issuer, key_id="c1", clock=lambda: NOW)
    v = OidcValidator(cfg, StaticJwks(fake.jwks()), clock=lambda: NOW)
    extra = {"token_use": "access", "client_id": [AUD, "other"]}
    _refused(v, fake.issue(sub="u", audience=AUD, drop=["aud"], extra=extra), "bad_audience")


def test_azp_is_not_enforced(issuer: FakeIssuer) -> None:
    """Decision: resource-bound access tokens carry the client in azp, not in aud."""
    token = issuer.issue(sub="u", audience=[AUD, "other"], extra={"azp": "other"})
    assert _validator(issuer).validate(token).subject == "u"


# 9. blank groups
@pytest.mark.parametrize("value", ["", "  ", [""], [" ", ""], []])
def test_blank_groups_normalise_to_none(issuer: FakeIssuer, value: object) -> None:
    token = issuer.issue(sub="u", audience=AUD, extra={"groups": value})
    assert _validator(issuer).validate(token).groups == ()


def test_blank_entries_dropped_from_a_list(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u", audience=AUD, extra={"groups": ["g-1", "", "g-2"]})
    assert _validator(issuer).validate(token).groups == ("g-1", "g-2")


# 6. named tests for the surviving mutants
def test_jwks_entry_with_use_enc_is_ignored(issuer: FakeIssuer) -> None:
    assert _get(_jwk(issuer, use="enc"), "k1") is None
    assert _get(_jwk(issuer, use="sig"), "k1") is not None


def test_duplicate_claim_names_refused(issuer: FakeIssuer) -> None:
    body = b'{"iss":"%s","aud":"%s","sub":"a","sub":"admin","exp":%d}' % (
        ISS.encode(),
        AUD.encode(),
        NOW + 99,
    )
    _refused(_validator(issuer), issuer.issue_raw(payload=body), "malformed")


def test_oversize_token_refused_even_if_validly_signed(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u", audience=AUD, extra={"pad": "x" * 20_000})
    assert len(token) > 16 * 1024
    _refused(_validator(issuer), token, "malformed")


def test_es256_signature_with_padding_byte_refused() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    v = OidcValidator(_config(algorithms=("ES256",)), StaticJwks(fake.jwks()), clock=lambda: NOW)
    head, body, sig = fake.issue(sub="u", audience=AUD).split(".")
    raw = base64.urlsafe_b64decode(sig + "==")
    assert v.validate(f"{head}.{body}.{sig}").subject == "u"
    padded = _b64(raw[:32] + b"\x00" + raw[32:])  # 65 bytes: same r and s, so it would verify
    _refused(v, f"{head}.{body}.{padded}", "bad_signature")


def test_ec_jwk_with_other_curve_ignored() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    assert _get(_jwk(fake, crv="P-384"), "e1") is None
    assert _get(_jwk(fake, crv=None), "e1") is None
    assert _get(_jwk(fake), "e1") is not None


def test_off_curve_point_ignored() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    assert _get(_jwk(fake, y=_b64(b"\x01" * 32)), "e1") is None


def test_nbf_inside_leeway_accepted_outside_refused(issuer: FakeIssuer) -> None:
    v = _validator(issuer, leeway_seconds=60)
    assert v.validate(issuer.issue(sub="u", audience=AUD, extra={"nbf": NOW + 60})).subject == "u"
    _refused(v, issuer.issue(sub="u", audience=AUD, extra={"nbf": NOW + 61}), "not_yet_valid")


def test_exp_is_exclusive_at_the_leeway_boundary(issuer: FakeIssuer) -> None:
    v0 = _validator(issuer, leeway_seconds=0)
    _refused(v0, issuer.issue(sub="u", audience=AUD, expires_in=0), "expired")
    assert v0.validate(issuer.issue(sub="u", audience=AUD, expires_in=1)).subject == "u"
    v60 = _validator(issuer, leeway_seconds=60)
    _refused(v60, issuer.issue(sub="u", audience=AUD, expires_in=-60), "expired")
    assert v60.validate(issuer.issue(sub="u", audience=AUD, expires_in=-59)).subject == "u"


class SpyJwks:
    def __init__(self, inner: StaticJwks) -> None:
        self.inner = inner
        self.asked: list[object] = []

    def get(self, kid: str) -> Jwk | None:
        self.asked.append(kid)
        return self.inner.get(kid)


@pytest.mark.parametrize("kid", [7, ["k1"], {"a": 1}, True, ""])
def test_non_string_kid_never_reaches_the_key_source(issuer: FakeIssuer, kid: object) -> None:
    spy = SpyJwks(StaticJwks(issuer.jwks()))
    v = OidcValidator(_config(), spy, clock=lambda: NOW)
    _refused(v, issuer.issue(sub="u", audience=AUD, header={"kid": kid}), "unknown_key")
    assert spy.asked == []


@pytest.mark.parametrize("sub", [123, "", None, ["u"], True])
def test_bad_subject_refused(issuer: FakeIssuer, sub: object) -> None:
    token = issuer.issue(sub="x", audience=AUD, extra={"sub": sub})
    _refused(_validator(issuer), token, "missing_claim")


def test_ttl_refresh_is_rate_limited() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
    fetch, now = Fetch(fake), [1000.0]
    v, _ = _cached(fetch, now)
    token = fake.issue(sub="u", audience=AUD)
    v.validate(token)
    fetch.fail = OSError("down")
    now[0] += 301
    for _ in range(20):
        v.validate(token)
    assert fetch.calls == 2
    now[0] += 31
    v.validate(token)
    assert fetch.calls == 3


def test_config_refuses_unsafe_values() -> None:
    with pytest.raises(ValueError, match="jwks_uri"):
        OidcConfig(issuer=ISS, audience=AUD, jwks_uri="http://idp.example.test/jwks")
    with pytest.raises(ValueError, match="audience"):
        OidcConfig(issuer=ISS, audience="")
    with pytest.raises(ValueError, match="issuer"):
        OidcConfig(issuer="https://", audience=AUD)
    with pytest.raises(ValueError, match="issuer"):
        OidcConfig(issuer="https://idp.example.test/a b", audience=AUD)
    with pytest.raises(ValueError, match="leeway"):
        OidcConfig(issuer=ISS, audience=AUD, leeway_seconds=301)
    assert OidcConfig(issuer=ISS, audience=AUD, leeway_seconds=300).leeway_seconds == 300


def test_cache_config_refuses_unsafe_values() -> None:
    with pytest.raises(ValueError, match="positive"):
        CachedJwks(URI, lambda _u: b"", ttl_seconds=0)
    with pytest.raises(ValueError, match="positive"):
        CachedJwks(URI, lambda _u: b"", min_refetch_seconds=0)
    with pytest.raises(ValueError, match="max_stale"):
        CachedJwks(URI, lambda _u: b"", ttl_seconds=100, max_stale_seconds=99)


def test_cache_uses_a_monotonic_clock_by_default() -> None:
    assert CachedJwks(URI, lambda _u: b"")._clock is time.monotonic


def test_cognito_region_must_match_the_pool() -> None:
    with pytest.raises(ValueError, match="match"):
        cognito_config(region="us-east-1", user_pool_id="eu-west-2_ABC123", client_id="c")
    with pytest.raises(ValueError, match="region"):
        cognito_config(region="eu-west-٢", user_pool_id="eu-west-٢_ABC", client_id="c")


# --- small fixes ---------------------------------------------------------------------------


@pytest.mark.parametrize("codec", ["utf-16", "utf-32", "utf-8-sig"])
def test_non_utf8_payloads_refused(issuer: FakeIssuer, codec: str) -> None:
    text = json.dumps({"iss": ISS, "aud": AUD, "sub": "u", "exp": NOW + 99})
    _refused(_validator(issuer), issuer.issue_raw(payload=text.encode(codec)), "malformed")


def test_private_jwk_entry_ignored(issuer: FakeIssuer) -> None:
    assert _get(_jwk(issuer, d=_b64(b"secret")), "k1") is None


def test_jwk_alg_must_match_the_header_alg() -> None:
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    cfg = _config(algorithms=("RS256", "ES256"))
    v = OidcValidator(cfg, StaticJwks({"keys": [_jwk(fake, alg="RS256")]}), clock=lambda: NOW)
    _refused(v, fake.issue(sub="u", audience=AUD), "bad_algorithm")
    ok = OidcValidator(cfg, StaticJwks({"keys": [_jwk(fake, alg="ES256")]}), clock=lambda: NOW)
    assert ok.validate(fake.issue(sub="u", audience=AUD)).subject == "u"


def test_duplicate_kid_drops_both_entries(issuer: FakeIssuer) -> None:
    assert _get([_jwk(issuer), _jwk(issuer)], "k1") is None
    assert _get([_jwk(issuer), _jwk(issuer, kid="k9")], "k9") is not None


def test_key_ops_must_allow_verify(issuer: FakeIssuer) -> None:
    assert _get(_jwk(issuer, key_ops=["sign"]), "k1") is None
    assert _get(_jwk(issuer, key_ops="verify"), "k1") is None
    assert _get(_jwk(issuer, key_ops=["verify"]), "k1") is not None


def test_rsa_key_policy(issuer: FakeIssuer) -> None:
    n = int.from_bytes(base64.urlsafe_b64decode(str(_jwk(issuer)["n"]) + "=="), "big")

    def enc(v: int) -> str:
        return _b64(v.to_bytes((v.bit_length() + 7) // 8, "big"))

    assert _get(_jwk(issuer, n=enc(n ^ 1)), "k1") is None  # even modulus
    assert _get(_jwk(issuer, n=enc((1 << 8200) | 1)), "k1") is None  # over 8192 bits
    assert _get(_jwk(issuer, e=enc(3)), "k1") is None  # small exponent
    assert _get(_jwk(issuer), "k1") is not None


def test_verified_token_claims_are_read_only_and_not_hashed(issuer: FakeIssuer) -> None:
    token = issuer.issue(sub="u", audience=AUD, extra={"nested": {"a": [1, 2]}})
    got = _validator(issuer).validate(token)
    with pytest.raises(TypeError):
        got.claims["sub"] = "admin"  # type: ignore[index]
    with pytest.raises(TypeError):
        got.claims["nested"]["a"] = 1
    assert got.claims["nested"]["a"] == (1, 2)
    again = _validator(issuer).validate(issuer.issue(sub="u", audience=AUD, extra={"x": 1}))
    assert hash(got) is not None
    assert got.subject == again.subject


def test_config_algorithm_list_is_enforced_for_every_supported_algorithm() -> None:
    """RS256-only config refuses a genuine ES256 token, even from a key with no ``alg``."""
    fake = FakeIssuer(issuer=ISS, key_id="e1", algorithm="ES256", clock=lambda: NOW)
    v = OidcValidator(
        _config(algorithms=("RS256",)),
        StaticJwks({"keys": [_jwk(fake, alg=None)]}),
        clock=lambda: NOW,
    )
    _refused(v, fake.issue(sub="u", audience=AUD), "bad_algorithm")


def test_nan_constant_in_any_claim_refused(issuer: FakeIssuer) -> None:
    for const in (b"NaN", b"Infinity", b"-Infinity"):
        body = b'{"iss":"%s","aud":"%s","sub":"u","exp":%d,"x":%s}' % (
            ISS.encode(),
            AUD.encode(),
            NOW + 99,
            const,
        )
        _refused(_validator(issuer), issuer.issue_raw(payload=body), "malformed")


def test_payload_must_be_strict_utf8(issuer: FakeIssuer) -> None:
    body = b'{"iss":"%s","aud":"%s","sub":"caf\xe9","exp":%d}' % (
        ISS.encode(),
        AUD.encode(),
        NOW + 99,
    )
    _refused(_validator(issuer), issuer.issue_raw(payload=body), "malformed")
