"""Signed step context (D5-19): token verification fails closed, and the broker enforces scope."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import threading
import types
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sto.agents.step_token import (
    AUDIENCE,
    ISSUER,
    MAX_JTI,
    MAX_LEEWAY,
    MAX_TOKEN_BYTES,
    MAX_TOOL_NAME,
    MAX_TOOLS,
    MAX_TTL,
    AttemptDirectory,
    AttemptRecord,
    InProcessReissuer,
    JwksVerifier,
    StepContext,
    StepTokenError,
    StepTokenVerifier,
    mint_step_token,
)
from sto.budget.broker import (
    MAX_SK_LEN,
    InMemoryAttemptDirectory,
    StepBroker,
    new_attempt_secret,
)
from sto.domain.errors import TransientError
from sto.signing.local import LocalSigner
from sto.signing.port import Signature, Signer, SigningError
from sto.store.memory import MemoryStore
from sto.store.ports import Key, TeamScope

NOW = 1_800_000_000
SHA = "a" * 40
SECRET = b"k" * 32
SHORT_SECRET = b"j" * 32


def ctx(**over: Any) -> StepContext:
    base: dict[str, Any] = {
        "team": "alpha",
        "run": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "stage": "implement",
        "visit": 1,
        "attempt": 1,
        "tools": ("repo.read", "ticket.read"),
        "repo": "acme/widgets",
        "sha": SHA,
    }
    base.update(over)
    return StepContext(**base)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def dump(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


class RsaSigner:
    """Test RS256 signer; stands in for the KMS signer (D11-23)."""

    algorithm = "RS256"

    def __init__(self, key_id: str = "rsa-1", bits: int = 2048) -> None:
        self.key_id = key_id
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=bits)

    def sign(self, message: bytes) -> Signature:
        sig = self._key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return Signature(key_id=self.key_id, algorithm="RS256", value=sig)

    def verify(self, message: bytes, signature: Signature) -> bool:
        return JwksVerifier({"keys": list(self.public_keys())}).verify(message, signature)

    def public_keys(self) -> list[dict[str, str]]:
        nums = self._key.public_key().public_numbers()

        def enc(i: int) -> str:
            return b64(i.to_bytes((i.bit_length() + 7) // 8, "big"))

        return [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": self.key_id,
                 "n": enc(nums.n), "e": enc(nums.e)}]  # fmt: skip


@pytest.fixture(scope="module")
def rsa_signer() -> RsaSigner:
    return RsaSigner()


@pytest.fixture
def hs() -> LocalSigner:
    return LocalSigner(key_id="step-1", secret=SECRET)


def hs_verifier(signer: LocalSigner, **kw: Any) -> StepTokenVerifier:
    return StepTokenVerifier(signer, algorithm="HS256", **kw)


HEAD: dict[str, Any] = {"alg": "HS256", "kid": "step-1", "typ": "JWT"}


def forge(signer: Any, header: dict[str, Any], claims: dict[str, Any]) -> str:
    """Sign arbitrary header and claims with a real signer."""
    signing_input = f"{b64(dump(header))}.{b64(dump(claims))}"
    return f"{signing_input}.{b64(signer.sign(signing_input.encode()).value)}"


def good_claims(**over: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "iss": ISSUER, "aud": AUDIENCE, "team": "alpha", "run": "R1", "stage": "implement",
        "visit": 1, "attempt": 1, "tools": ["repo.read"], "repo": "acme/widgets", "sha": SHA,
        "iat": NOW, "nbf": NOW, "exp": NOW + 300, "jti": "j1",
    }  # fmt: skip
    c.update(over)
    return c


def attempt(fn: Any, *a: Any, **kw: Any) -> tuple[Any, str | None]:
    """Call ``fn``; return ``(value, None)`` or ``(None, reason)`` so a refusal is an assertion."""
    try:
        return fn(*a, **kw), None
    except StepTokenError as exc:
        return None, exc.reason


def reason(fn: Any, *a: Any, **kw: Any) -> str:
    with pytest.raises(StepTokenError) as info:
        fn(*a, **kw)
    return info.value.reason


# -- happy path ---------------------------------------------------------------------------------


def test_round_trip_returns_the_exact_context(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    got = hs_verifier(hs).verify(token, now=NOW + 1, stage="implement")
    assert got.context == ctx()
    assert (got.iat, got.exp) == (NOW, NOW + 300)


# -- expiry and clock skew ----------------------------------------------------------------------


def test_expired_token_is_refused_at_exp_exactly(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW, ttl=60)
    v = hs_verifier(hs)
    v.verify(token, now=NOW + 59)
    assert reason(v.verify, token, now=NOW + 60) == "expired"
    assert reason(v.verify, token, now=NOW + 10_000) == "expired"


def test_leeway_extends_expiry_by_exactly_leeway(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW, ttl=60)
    v = hs_verifier(hs, leeway=5)
    v.verify(token, now=NOW + 64)
    assert reason(v.verify, token, now=NOW + 65) == "expired"


def test_token_from_the_future_is_refused_beyond_leeway(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    v = hs_verifier(hs, leeway=5)
    v.verify(token, now=NOW - 5)
    assert reason(v.verify, token, now=NOW - 6) == "not yet valid"
    assert reason(hs_verifier(hs).verify, token, now=NOW - 1) == "not yet valid"


def test_not_before_is_enforced_separately_from_iat(hs: LocalSigner) -> None:
    token = forge(hs, HEAD, good_claims(nbf=NOW + 100))
    assert reason(hs_verifier(hs).verify, token, now=NOW + 50) == "not yet valid"
    hs_verifier(hs).verify(token, now=NOW + 100)


def test_leeway_is_capped(hs: LocalSigner) -> None:
    hs_verifier(hs, leeway=MAX_LEEWAY)
    with pytest.raises(StepTokenError):
        hs_verifier(hs, leeway=MAX_LEEWAY + 1)
    with pytest.raises(StepTokenError):
        hs_verifier(hs, leeway=-1)


def test_lifetime_is_capped_at_mint_and_at_verify(hs: LocalSigner) -> None:
    with pytest.raises(StepTokenError):
        mint_step_token(hs, ctx(), now=NOW, ttl=MAX_TTL + 1)
    with pytest.raises(StepTokenError):
        mint_step_token(hs, ctx(), now=NOW, ttl=0)
    long = forge(hs, HEAD, good_claims(exp=NOW + MAX_TTL + 1))
    assert reason(hs_verifier(hs).verify, long, now=NOW) == "bad lifetime"
    slow = mint_step_token(hs, ctx(), now=NOW, ttl=101)
    assert reason(hs_verifier(hs, max_ttl=100).verify, slow, now=NOW) == "bad lifetime"


# -- stage, issuer, audience --------------------------------------------------------------------


def test_wrong_stage_is_refused(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(stage="review"), now=NOW)
    assert reason(hs_verifier(hs).verify, token, now=NOW, stage="implement") == "wrong stage"


def test_expired_wrong_stage_reports_expiry(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(stage="review"), now=NOW, ttl=10)
    assert reason(hs_verifier(hs).verify, token, now=NOW + 99, stage="implement") == "expired"


def test_audience_and_issuer_are_bound(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW, audience="gateway")
    assert reason(hs_verifier(hs).verify, token, now=NOW) == "wrong audience"
    hs_verifier(hs, audience="gateway").verify(token, now=NOW)
    other = mint_step_token(hs, ctx(), now=NOW, issuer="someone-else")
    assert reason(hs_verifier(hs).verify, other, now=NOW) == "wrong issuer"


def test_audience_list_is_refused(hs: LocalSigner) -> None:
    token = forge(hs, HEAD, good_claims(aud=[AUDIENCE]))
    assert reason(hs_verifier(hs).verify, token, now=NOW) == "wrong audience"


@pytest.mark.parametrize(
    "bad",
    [
        {"team": ""}, {"team": 5}, {"visit": 0}, {"visit": True}, {"visit": "1"},
        {"attempt": 1.0}, {"tools": "repo.read"}, {"tools": ["a", "a"]}, {"tools": [1]},
        {"sha": "main"}, {"sha": "A" * 40}, {"repo": " "}, {"jti": ""}, {"iat": "1"},
        {"exp": True},
    ],
)  # fmt: skip
def test_every_claim_is_validated(hs: LocalSigner, bad: dict[str, Any]) -> None:
    token = forge(hs, HEAD, good_claims(**bad))
    assert reason(hs_verifier(hs).verify, token, now=NOW + 1) in {"bad claims", "bad lifetime"}


def test_missing_and_extra_claims_are_refused(hs: LocalSigner) -> None:
    head = HEAD
    missing = good_claims()
    del missing["sha"]
    assert reason(hs_verifier(hs).verify, forge(hs, head, missing), now=NOW) == "bad claims"
    extra = good_claims(admin=True)
    assert reason(hs_verifier(hs).verify, forge(hs, head, extra), now=NOW) == "bad claims"


# -- tampering, algorithm pinning ---------------------------------------------------------------


def swap_part(token: str, index: int, data: bytes) -> str:
    parts = token.split(".")
    parts[index] = b64(data)
    return ".".join(parts)


def test_tampered_payload_is_refused(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    claims["team"] = "beta"
    assert (
        reason(hs_verifier(hs).verify, swap_part(token, 1, dump(claims)), now=NOW)
        == "bad signature"
    )


def test_tampered_signature_and_truncation_are_refused(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    head, body, sig = token.split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    v = hs_verifier(hs)
    assert reason(v.verify, f"{head}.{body}.{flipped}", now=NOW) == "bad signature"
    assert reason(v.verify, f"{head}.{body}.", now=NOW) == "malformed token"
    assert reason(v.verify, f"{head}.{body}", now=NOW) == "malformed token"
    assert reason(v.verify, f"{head}.{body}.{sig}.x", now=NOW) == "malformed token"
    assert reason(v.verify, "", now=NOW) == "malformed token"


def test_unknown_key_and_foreign_key_are_refused(hs: LocalSigner) -> None:
    other = LocalSigner(key_id="step-1", secret=SHORT_SECRET)  # same kid, different secret
    assert (
        reason(hs_verifier(hs).verify, mint_step_token(other, ctx(), now=NOW), now=NOW)
        == "bad signature"
    )
    rotated = LocalSigner(key_id="step-2", secret=SECRET)
    assert (
        reason(hs_verifier(hs).verify, mint_step_token(rotated, ctx(), now=NOW), now=NOW)
        == "bad signature"
    )


def test_retired_key_still_verifies(hs: LocalSigner) -> None:
    new = LocalSigner(key_id="step-2", secret=SHORT_SECRET, retired={"step-1": SECRET})
    token = mint_step_token(hs, ctx(), now=NOW)
    hs_verifier(new).verify(token, now=NOW)


def test_alg_none_is_refused(hs: LocalSigner) -> None:
    for alg in ("none", "None", "NONE", ""):
        head = b64(dump({"alg": alg, "kid": "step-1", "typ": "JWT"}))
        token = f"{head}.{b64(dump(good_claims()))}."
        assert reason(hs_verifier(hs).verify, token, now=NOW) == "algorithm not allowed"
        token = f"{head}.{b64(dump(good_claims()))}.{b64(b'x')}"
        assert reason(hs_verifier(hs).verify, token, now=NOW) == "algorithm not allowed"


def test_header_algorithm_must_equal_the_pinned_one(hs: LocalSigner) -> None:
    token = forge(hs, {"alg": "HS384", "kid": "step-1", "typ": "JWT"}, good_claims())
    assert reason(hs_verifier(hs).verify, token, now=NOW) == "algorithm not allowed"
    lower = forge(hs, {**HEAD, "alg": "hs256"}, good_claims())
    assert reason(hs_verifier(hs).verify, lower, now=NOW) == "algorithm not allowed"


def test_key_confusion_hs256_with_public_key_as_secret_is_refused(rsa_signer: RsaSigner) -> None:
    """The classic attack: sign HS256 using the published RSA key bytes as the HMAC secret."""
    jwks = JwksVerifier({"keys": rsa_signer.public_keys()})
    n = rsa_signer.public_keys()[0]["n"]
    forged_with = LocalSigner(key_id="rsa-1", secret=n.encode().ljust(32, b"="))
    token = mint_step_token(forged_with, ctx(), now=NOW)
    pinned_rs = StepTokenVerifier(jwks, algorithm="RS256")
    assert reason(pinned_rs.verify, token, now=NOW) == "algorithm not allowed"


def test_pinned_hs256_refuses_an_rs256_header(rsa_signer: RsaSigner, hs: LocalSigner) -> None:
    token = mint_step_token(rsa_signer, ctx(), now=NOW)
    assert reason(hs_verifier(hs).verify, token, now=NOW) == "algorithm not allowed"


@pytest.mark.parametrize(
    "extra", [{"jku": "http://evil/jwks"}, {"jwk": {}}, {"crit": ["x"]}, {"x5u": "u"}]
)
def test_dangerous_header_fields_are_refused(hs: LocalSigner, extra: dict[str, Any]) -> None:
    head = {"alg": "HS256", "kid": "step-1", "typ": "JWT", **extra}
    assert reason(hs_verifier(hs).verify, forge(hs, head, good_claims()), now=NOW) == "bad header"


def test_header_typ_and_kid_are_required(hs: LocalSigner) -> None:
    no_typ = {"alg": "HS256", "kid": "step-1"}
    for head in (no_typ, {**HEAD, "kid": 1}, {**HEAD, "typ": "at+jwt"}):
        assert (
            reason(hs_verifier(hs).verify, forge(hs, head, good_claims()), now=NOW) == "bad header"
        )


def test_duplicate_keys_nonfinite_and_garbage_are_refused(hs: LocalSigner) -> None:
    v = hs_verifier(hs)
    head = b64(dump({"alg": "HS256", "kid": "step-1", "typ": "JWT"}))
    dup = b64(b'{"team":"alpha","team":"beta"}')
    assert reason(v.verify, f"{head}.{dup}.{b64(b'x')}", now=NOW) == "malformed token"
    nan = b64(b'{"exp":NaN}')
    assert reason(v.verify, f"{head}.{nan}.{b64(b'x')}", now=NOW) == "malformed token"
    for junk in ("a.b.c", "!!.!!.!!", f"{head}.{b64(b'[]')}.{b64(b'x')}", "é.é.é"):
        assert reason(v.verify, junk, now=NOW) == "malformed token"
    assert reason(v.verify, "a" * 9000, now=NOW) == "malformed token"
    assert reason(v.verify, 5, now=NOW) == "malformed token"


def test_non_canonical_base64_is_refused(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    head, body, sig = token.split(".")
    assert reason(hs_verifier(hs).verify, f"{head}.{body}.{sig}=", now=NOW) == "malformed token"


def test_verifier_error_never_leaks_the_token(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    bad = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
    with pytest.raises(StepTokenError) as info:
        hs_verifier(hs).verify(bad, now=NOW)
    assert token.split(".")[1] not in str(info.value)


# -- JWKS ---------------------------------------------------------------------------------------


def test_rs256_token_verifies_with_only_a_jwks_public_key(rsa_signer: RsaSigner) -> None:
    jwks = json.loads(json.dumps({"keys": rsa_signer.public_keys()}))  # as fetched over the wire
    verifier = StepTokenVerifier(JwksVerifier(jwks), algorithm="RS256")
    token = mint_step_token(rsa_signer, ctx(), now=NOW)
    assert verifier.verify(token, now=NOW).context == ctx()
    assert JwksVerifier(jwks).public_keys()[0]["kid"] == "rsa-1"
    assert not hasattr(JwksVerifier(jwks), "sign")


def test_jwks_verifier_refuses_a_forged_or_other_key_signature(rsa_signer: RsaSigner) -> None:
    verifier = StepTokenVerifier(
        JwksVerifier({"keys": rsa_signer.public_keys()}), algorithm="RS256"
    )
    attacker = RsaSigner("rsa-1")  # same kid, different key
    assert (
        reason(verifier.verify, mint_step_token(attacker, ctx(), now=NOW), now=NOW)
        == "bad signature"
    )
    unknown = RsaSigner("rsa-other")
    assert (
        reason(verifier.verify, mint_step_token(unknown, ctx(), now=NOW), now=NOW)
        == "bad signature"
    )


def test_jwks_rejects_unsafe_documents(rsa_signer: RsaSigner) -> None:
    good = rsa_signer.public_keys()[0]
    docs: list[dict[str, Any]] = [
        {},
        {"keys": []},
        {"keys": "x"},
        {"keys": [5]},
        {"keys": [{**good, "kty": "oct"}]},
        {"keys": [{**good, "alg": "HS256"}]},
        {"keys": [{**good, "kid": ""}]},
        {"keys": [good, good]},
        {"keys": [{**good, "n": b64(b"\x01" * 64)}]},  # 512-bit modulus
        {"keys": [{**good, "n": "!!"}]},
        {"keys": [{**good, "e": b64(b"\x02")}]},
    ]
    for doc in docs:
        with pytest.raises(SigningError):
            JwksVerifier(doc)


# -- token: extra gaps -------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["iat", "nbf", "exp"])
def test_float_times_are_refused(hs: LocalSigner, name: str) -> None:
    claims = good_claims(**{name: float(good_claims()[name])})
    assert reason(hs_verifier(hs).verify, forge(hs, HEAD, claims), now=NOW) == "bad claims"


def test_nbf_must_not_precede_iat_or_reach_exp(hs: LocalSigner) -> None:
    v = hs_verifier(hs)
    assert reason(v.verify, forge(hs, HEAD, good_claims(nbf=NOW - 1)), now=NOW) == "bad lifetime"
    equal = good_claims(nbf=NOW + 300)
    assert reason(v.verify, forge(hs, HEAD, equal), now=NOW + 300) == "bad lifetime"


def test_nbf_one_second_early_is_not_valid_with_zero_leeway(hs: LocalSigner) -> None:
    token = forge(hs, HEAD, good_claims(iat=NOW, nbf=NOW + 10, exp=NOW + 300))
    v = hs_verifier(hs)
    assert reason(v.verify, token, now=NOW + 9) == "not yet valid"
    assert v.verify(token, now=NOW + 10).nbf == NOW + 10
    assert reason(hs_verifier(hs, leeway=2).verify, token, now=NOW + 7) == "not yet valid"
    assert hs_verifier(hs, leeway=2).verify(token, now=NOW + 8).nbf == NOW + 10


def test_oversize_token_is_refused_even_when_validly_signed(hs: LocalSigner) -> None:
    token = forge(hs, HEAD, good_claims(jti="j" * 9000))
    assert len(token) > MAX_TOKEN_BYTES
    assert reason(hs_verifier(hs).verify, token, now=NOW) == "malformed token"


def test_mint_refuses_an_oversize_token(hs: LocalSigner) -> None:
    big = ctx(tools=tuple(f"{i:03d}" + "t" * (MAX_TOOL_NAME - 3) for i in range(MAX_TOOLS)))
    with pytest.raises(StepTokenError) as info:
        mint_step_token(hs, big, now=NOW)
    assert info.value.reason == "token too large"


def test_json_recursion_error_is_malformed_not_a_crash(
    hs: LocalSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CPython's C parser nests deeper than the 8 KiB size cap allows, so a real deep payload cannot
    # reach RecursionError here; other builds do. Simulate the parser raising it.
    def too_deep(*a: Any, **kw: Any) -> Any:
        raise RecursionError

    monkeypatch.setattr(json, "loads", too_deep)
    token = mint_step_token(hs, ctx(), now=NOW)
    assert reason(hs_verifier(hs).verify, token, now=NOW) == "malformed token"


def test_json_errors_do_not_chain_the_payload(hs: LocalSigner) -> None:
    head = b64(dump(HEAD))
    secret_body = b64(b'{"team": "visible-in-cause", oops')
    with pytest.raises(StepTokenError) as info:
        hs_verifier(hs).verify(f"{head}.{secret_body}.{b64(b'x')}", now=NOW)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__ is True


class RaisingVerifier:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def verify(self, message: bytes, signature: Signature) -> bool:
        raise self.exc

    def public_keys(self) -> list[dict[str, str]]:
        return []


def test_verifier_signing_error_is_a_refusal(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    v = StepTokenVerifier(RaisingVerifier(SigningError("bad")), algorithm="HS256")
    assert reason(v.verify, token, now=NOW) == "bad signature"


def test_transient_verifier_failure_stays_transient(hs: LocalSigner) -> None:
    token = mint_step_token(hs, ctx(), now=NOW)
    v = StepTokenVerifier(RaisingVerifier(TransientError("kms throttle")), algorithm="HS256")
    with pytest.raises(TransientError):
        v.verify(token, now=NOW)


@pytest.mark.parametrize("answer", [1, "yes", [1], object()])
def test_only_a_real_true_from_the_verifier_is_accepted(hs: LocalSigner, answer: Any) -> None:
    class Truthy:
        def verify(self, message: bytes, signature: Signature) -> Any:
            return answer

        def public_keys(self) -> list[dict[str, str]]:
            return []

    token = mint_step_token(hs, ctx(), now=NOW)
    assert (
        reason(StepTokenVerifier(Truthy(), algorithm="HS256").verify, token, now=NOW)
        == "bad signature"
    )  # noqa: E501


@pytest.mark.parametrize("bad", ["a\nb", "a\x00", "\ud800", "é", "x" * (MAX_JTI + 1)])
def test_jti_must_be_short_printable_ascii(hs: LocalSigner, bad: str) -> None:
    token = forge(hs, HEAD, good_claims(jti=bad))
    assert reason(hs_verifier(hs).verify, token, now=NOW) == "bad claims"


def test_jti_at_the_limit_is_accepted(hs: LocalSigner) -> None:
    token = forge(hs, HEAD, good_claims(jti="j" * MAX_JTI))
    assert hs_verifier(hs).verify(token, now=NOW).jti == "j" * MAX_JTI


def test_tool_count_and_name_limits(hs: LocalSigner) -> None:
    ok = tuple(f"t{i}" for i in range(MAX_TOOLS))
    assert ctx(tools=ok).tools == ok
    with pytest.raises(StepTokenError):
        ctx(tools=(*ok, "one-more"))
    assert ctx(tools=("t" * MAX_TOOL_NAME,)).tools
    for bad in ("t" * (MAX_TOOL_NAME + 1), " a", "a ", "a\nb", ""):
        with pytest.raises(StepTokenError):
            ctx(tools=(bad,))
    over = forge(hs, HEAD, good_claims(tools=[f"t{i}" for i in range(MAX_TOOLS + 1)]))
    assert reason(hs_verifier(hs).verify, over, now=NOW) == "bad claims"


def test_team_with_hash_is_refused_at_mint() -> None:
    with pytest.raises(StepTokenError):
        ctx(team="a#b")


def test_mint_refuses_an_inconsistent_signer(hs: LocalSigner) -> None:
    class Liar:
        algorithm = "HS256"
        key_id = "step-1"

        def __init__(self, sig: Signature) -> None:
            self.sig = sig

        def sign(self, message: bytes) -> Signature:
            return self.sig

    for sig in (Signature("other", "HS256", b"x"), Signature("step-1", "RS256", b"x")):
        with pytest.raises(StepTokenError):
            mint_step_token(Liar(sig), ctx(), now=NOW)  # type: ignore[arg-type]


# -- JWKS hardening -----------------------------------------------------------------------------


def jwk_with(rsa_signer: RsaSigner, **over: Any) -> dict[str, Any]:
    return {"keys": [{**rsa_signer.public_keys()[0], **over}]}


@pytest.mark.parametrize("member", ["d", "p", "q", "dp", "dq", "qi", "oth", "k"])
def test_every_private_member_is_refused(rsa_signer: RsaSigner, member: str) -> None:
    with pytest.raises(SigningError, match="private"):
        JwksVerifier(jwk_with(rsa_signer, **{member: "AQAB"}))


def test_public_keys_returns_only_allow_listed_members(rsa_signer: RsaSigner) -> None:
    doc = jwk_with(rsa_signer, x5u="http://evil", jku="http://evil", x5c=["x"], extra="y")
    (key,) = JwksVerifier(doc).public_keys()
    assert set(key) == {"kid", "kty", "alg", "use", "n", "e"}


@pytest.mark.parametrize("use", ["enc", "", None, 5])
def test_use_other_than_sig_is_refused(rsa_signer: RsaSigner, use: Any) -> None:
    with pytest.raises(SigningError):
        JwksVerifier(jwk_with(rsa_signer, use=use))


def test_absent_use_is_allowed(rsa_signer: RsaSigner) -> None:
    key = {k: v for k, v in rsa_signer.public_keys()[0].items() if k != "use"}
    assert JwksVerifier({"keys": [key]}).public_keys()[0]["kid"] == "rsa-1"


@pytest.mark.parametrize("ops", [["encrypt"], [], "verify", ["sign"], None])
def test_key_ops_without_verify_is_refused(rsa_signer: RsaSigner, ops: Any) -> None:
    with pytest.raises(SigningError):
        JwksVerifier(jwk_with(rsa_signer, key_ops=ops))


def test_key_ops_with_verify_is_allowed(rsa_signer: RsaSigner) -> None:
    JwksVerifier(jwk_with(rsa_signer, key_ops=["verify"]))


def test_a_key_just_under_the_minimum_size_is_refused() -> None:
    small = RsaSigner("rsa-2047", bits=2047)
    with pytest.raises(SigningError):
        JwksVerifier({"keys": small.public_keys()})


def test_leading_zero_bytes_in_n_or_e_are_refused(rsa_signer: RsaSigner) -> None:
    good = rsa_signer.public_keys()[0]
    n_raw = base64.urlsafe_b64decode(good["n"] + "==")
    for over in (
        {"n": b64(b"\x00" + n_raw)},
        {"e": b64(b"\x00\x01\x00\x01")},
    ):
        with pytest.raises(SigningError):
            JwksVerifier(jwk_with(rsa_signer, **over))
    JwksVerifier(jwk_with(rsa_signer))


def test_modulus_exponent_and_kid_limits(rsa_signer: RsaSigner) -> None:
    good = rsa_signer.public_keys()[0]
    n = int.from_bytes(base64.urlsafe_b64decode(good["n"] + "=="), "big")

    def enc(i: int) -> str:
        return b64(i.to_bytes((i.bit_length() + 7) // 8, "big"))

    for over in (
        {"n": enc(n - 1)},  # even modulus
        {"n": enc((1 << 8200) + 1)},  # too big
        {"e": enc(3)},
        {"e": enc(65536)},
        {"kid": "a\nb"},
        {"kid": "a\x00"},
    ):
        with pytest.raises(SigningError):
            JwksVerifier(jwk_with(rsa_signer, **over))


# -- reissuer and broker ------------------------------------------------------------------------


class Flags:
    def __init__(self) -> None:
        self.raised: list[tuple[StepContext, str, str]] = []

    def raise_flag(self, context: StepContext, name: str, detail: str) -> None:
        self.raised.append((context, name, detail))


class Env:
    def __init__(
        self,
        signer: LocalSigner,
        *,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        reissue_issuer: str | None = None,
        reissue_audience: str | None = None,
    ) -> None:
        self.signer = signer
        self.issuer, self.audience = issuer, audience
        self.store = MemoryStore()
        self.directory = InMemoryAttemptDirectory()
        self.flags = Flags()
        self.verifier = hs_verifier(signer, issuer=issuer, audience=audience)
        self.reissuer = InProcessReissuer(
            signer,
            hs_verifier(
                signer, issuer=reissue_issuer or issuer, audience=reissue_audience or audience
            ),
            self.directory,
            issuer=reissue_issuer or issuer,
            audience=reissue_audience or audience,
        )
        self.broker = StepBroker(
            verifier=self.verifier,
            reissuer=self.reissuer,
            directory=self.directory,
            store=self.store,
            flags=self.flags,
        )

    def start(
        self, context: StepContext | None = None, *, deadline: int = NOW + 7200, ttl: int = 300
    ) -> tuple[StepContext, str, bytes]:
        context = context or ctx()
        secret = new_attempt_secret()
        self.directory.register(context, secret, deadline=deadline)
        token = mint_step_token(
            self.signer, context, now=NOW, ttl=ttl, issuer=self.issuer, audience=self.audience
        )
        return context, token, secret


@pytest.fixture
def env(hs: LocalSigner) -> Env:
    return Env(hs)


def test_attempt_secret_is_long_and_random() -> None:
    assert len(new_attempt_secret()) >= 32
    assert new_attempt_secret() != new_attempt_secret()


def _reachable(root: object) -> list[object]:
    """Every object reachable through attributes, slots and containers, but not through functions
    or bound methods (a remote callback is opaque, so its target is not part of the broker)."""
    seen: dict[int, object] = {}
    todo = [root]
    while todo:
        obj = todo.pop()
        if id(obj) in seen or isinstance(obj, (str, bytes, int, float, bool, type(None))):
            continue
        seen[id(obj)] = obj
        if isinstance(obj, (types.FunctionType, types.MethodType, types.BuiltinFunctionType)):
            continue
        if isinstance(obj, dict):
            todo.extend([*obj.keys(), *obj.values()])
        elif isinstance(obj, (list, tuple, set, frozenset)):
            todo.extend(obj)
        else:
            todo.extend(getattr(obj, "__dict__", {}).values())
            for klass in type(obj).__mro__:
                for slot in getattr(klass, "__slots__", ()):
                    if hasattr(obj, slot):
                        todo.append(getattr(obj, slot))
    return list(seen.values())


def test_broker_holds_no_signing_power(rsa_signer: RsaSigner) -> None:
    """Wire the broker the way a deployment does: a public-key verifier and a remote reissuer."""
    verifier = StepTokenVerifier(
        JwksVerifier({"keys": rsa_signer.public_keys()}), algorithm="RS256"
    )
    directory = InMemoryAttemptDirectory()
    dispatcher = InProcessReissuer(rsa_signer, verifier, directory)

    class Remote:
        """What the broker holds: a call back to the dispatcher, with no signer inside."""

        def __init__(self, call: Any) -> None:
            self._call = call
            self.ttl = dispatcher.ttl

        def reissue(self, token: str, secret: bytes, *, now: int) -> str:
            return str(self._call(token, secret, now=now))

    broker = StepBroker(
        verifier=verifier,
        reissuer=Remote(dispatcher.reissue),
        directory=directory,
        store=MemoryStore(),
        flags=Flags(),
    )
    graph = _reachable(broker)
    assert len(graph) > 5  # the walk really went somewhere
    assert not [o for o in graph if isinstance(o, Signer) or callable(getattr(o, "sign", None))]
    assert "signer" not in inspect.signature(StepBroker.__init__).parameters
    # and a sanity check that the walk would find one
    leaky = Remote(dispatcher.reissue)
    leaky.signer = rsa_signer  # type: ignore[attr-defined]
    assert [o for o in _reachable(leaky) if isinstance(o, Signer)]


def test_directory_stores_a_digest_not_the_secret(env: Env) -> None:
    context, _, secret = env.start()
    record = env.directory.attempt(context)
    assert record is not None
    assert record.secret_digest == hashlib.sha256(secret).digest()
    assert isinstance(env.directory, AttemptDirectory)


def test_attempt_record_repr_hides_the_digest() -> None:
    record = AttemptRecord(context=ctx(), secret_digest=hashlib.sha256(b"x").digest(), deadline=NOW)
    assert "secret_digest" not in repr(record)
    assert record.secret_digest.hex() not in repr(record)
    assert repr(record) == f"AttemptRecord(deadline={NOW}, live=True)"


def test_attempt_record_validates_every_field() -> None:
    digest = hashlib.sha256(b"x").digest()
    AttemptRecord(context=ctx(), secret_digest=digest, deadline=NOW, live=False)
    bad: list[dict[str, Any]] = [
        {"live": 1}, {"live": None}, {"live": "yes"},
        {"secret_digest": digest[:-1]}, {"secret_digest": digest + b"x"},
        {"secret_digest": digest.hex()}, {"deadline": float("inf")}, {"deadline": True},
        {"deadline": -1}, {"context": object()}, {"context": None},
    ]  # fmt: skip
    for over in bad:
        kw: dict[str, Any] = {"context": ctx(), "secret_digest": digest, "deadline": NOW} | over
        with pytest.raises(StepTokenError):
            AttemptRecord(**kw)


def test_register_validates_secret_and_deadline(env: Env) -> None:
    c = ctx()
    for secret in (b"short", b"", "s" * 40):
        with pytest.raises(StepTokenError):
            env.directory.register(c, secret, deadline=NOW + 10)  # type: ignore[arg-type]
    for deadline in (float("nan"), float("inf"), 1.5e9, True, "9", None, -1):
        with pytest.raises(StepTokenError):
            env.directory.register(c, new_attempt_secret(), deadline=deadline)  # type: ignore[arg-type]
    assert env.directory.attempt(c) is None


def test_refresh_issues_a_new_token_with_identical_claims(env: Env) -> None:
    context, token, secret = env.start()
    new, err = attempt(env.broker.refresh, token, secret, now=NOW + 200)
    assert err is None
    assert new != token
    got = hs_verifier(env.signer).verify(new or "", now=NOW + 201)
    assert got.context == context
    assert got.exp == NOW + 200 + 300
    assert got.jti != hs_verifier(env.signer).verify(token, now=NOW + 1).jti


class SpyReissuer:
    ttl = 300

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.calls: list[tuple[str, bytes, int]] = []

    def reissue(self, token: str, secret: bytes, *, now: int) -> str:
        self.calls.append((token, secret, now))
        return str(self.inner.reissue(token, secret, now=now))


def spied(env: Env) -> SpyReissuer:
    spy = SpyReissuer(env.reissuer)
    env.broker._reissuer = spy  # noqa: SLF001
    return spy


def test_refresh_passes_the_token_secret_and_callers_clock(env: Env) -> None:
    spy = spied(env)
    _, token, secret = env.start()
    _, err = attempt(env.broker.refresh, token, secret, now=NOW + 5)
    assert err is None
    assert spy.calls == [(token, secret, NOW + 5)]


def test_the_reissuer_is_not_called_for_a_wrong_secret_dead_or_expired_step(env: Env) -> None:
    spy = spied(env)
    context, token, secret = env.start()
    assert reason(env.broker.refresh, token, new_attempt_secret(), now=NOW) == "bad attempt secret"
    assert reason(env.broker.refresh, token, secret, now=NOW + 300) == "expired"
    env.directory.end(context)
    assert reason(env.broker.refresh, token, secret, now=NOW) == "step not live"
    assert spy.calls == []


def test_refresh_keeps_a_non_default_issuer_and_audience(hs: LocalSigner) -> None:
    e = Env(hs, issuer="sto-prod", audience="gateway")
    context, token, secret = e.start()
    new, err = attempt(e.broker.refresh, token, secret, now=NOW + 100)
    assert err is None
    assert e.verifier.verify(new or "", now=NOW + 100).context == context
    # and only the same issuer and audience: the default verifier refuses it
    assert reason(hs_verifier(hs).verify, new, now=NOW + 100) == "wrong issuer"


def test_refresh_refuses_a_reissuer_that_changes_audience_or_issuer(hs: LocalSigner) -> None:
    _, token, secret = (e := Env(hs, audience="gateway", reissue_audience="other")).start()
    assert reason(e.broker.refresh, token, secret, now=NOW + 1) == "wrong audience"
    _, token, secret = (e := Env(hs, issuer="a", reissue_issuer="b")).start()
    assert reason(e.broker.refresh, token, secret, now=NOW + 1) == "wrong issuer"


def test_refresh_refuses_a_reissuer_that_changes_the_context(env: Env) -> None:
    class Widening:
        ttl = 300

        def reissue(self, token: str, secret: bytes, *, now: int) -> str:
            wider = ctx(tools=("repo.read", "ticket.read", "repo.write"))
            return mint_step_token(env.signer, wider, now=now)

    broker = StepBroker(
        verifier=env.verifier, reissuer=Widening(), directory=env.directory,
        store=env.store, flags=env.flags,
    )  # fmt: skip
    _, token, secret = env.start()
    assert reason(broker.refresh, token, secret, now=NOW) == "reissued token changed the context"


def test_refresh_refuses_a_reissuer_that_outlives_the_deadline(env: Env) -> None:
    class Greedy:
        ttl = 300

        def reissue(self, token: str, secret: bytes, *, now: int) -> str:
            return mint_step_token(env.signer, ctx(), now=now, ttl=300)

    broker = StepBroker(
        verifier=env.verifier, reissuer=Greedy(), directory=env.directory,
        store=env.store, flags=env.flags,
    )  # fmt: skip
    _, token, secret = env.start(deadline=NOW + 100)
    assert reason(broker.refresh, token, secret, now=NOW + 50) == "reissued token outlives the step"


class FixedTtl:
    def __init__(self, ttl: int) -> None:
        self.ttl = ttl

    def reissue(self, token: str, secret: bytes, *, now: int) -> str:
        return ""


def test_broker_checks_reissuer_ttl_at_construction(env: Env) -> None:
    verifier = hs_verifier(env.signer, max_ttl=300)
    for ttl in (0, -1, MAX_TTL + 1, 301):
        with pytest.raises(StepTokenError):
            StepBroker(
                verifier=verifier,
                reissuer=FixedTtl(ttl),
                directory=env.directory,
                store=env.store,
                flags=env.flags,
            )
    StepBroker(
        verifier=verifier,
        reissuer=FixedTtl(300),
        directory=env.directory,
        store=env.store,
        flags=env.flags,
    )
    with pytest.raises(StepTokenError):
        InProcessReissuer(env.signer, env.verifier, env.directory, ttl=0)
    with pytest.raises(StepTokenError):
        InProcessReissuer(env.signer, env.verifier, env.directory, ttl=MAX_TTL + 1)


def test_reissuer_clamps_to_the_deadline_and_checks_it(env: Env) -> None:
    c = ctx()
    r = env.reissuer
    _, token, secret = env.start(c, deadline=NOW + 100)
    with pytest.raises(StepTokenError, match="deadline passed"):
        r.reissue(token, secret, now=NOW + 100)
    clamped = r.reissue(token, secret, now=NOW + 90)
    assert env.verifier.verify(clamped, now=NOW + 90).exp == NOW + 100


# -- the reissuer defends itself: direct calls with no broker in front --------------------------


def test_reissuer_refuses_widened_tools(env: Env) -> None:
    _, _, secret = env.start()
    wider = mint_step_token(env.signer, ctx(tools=("repo.read", "repo.write")), now=NOW)
    assert (
        reason(env.reissuer.reissue, wider, secret, now=NOW)
        == "context differs from the registered attempt"
    )


@pytest.mark.parametrize(
    "over",
    [{"repo": "evil/x"}, {"sha": "b" * 40}, {"tools": ()}, {"tools": ("ticket.read", "repo.read")}],
)
def test_reissuer_refuses_any_difference_from_the_registered_context(
    env: Env, over: dict[str, Any]
) -> None:
    _, _, secret = env.start()
    other = mint_step_token(env.signer, ctx(**over), now=NOW)
    assert (
        reason(env.reissuer.reissue, other, secret, now=NOW)
        == "context differs from the registered attempt"
    )


def test_reissuer_refuses_another_teams_live_attempt_without_its_secret(env: Env) -> None:
    env.start(ctx(team="alpha"))
    _, beta_token, _ = env.start(ctx(team="beta"))
    attacker_secret = new_attempt_secret()
    assert (
        reason(env.reissuer.reissue, beta_token, attacker_secret, now=NOW) == "bad attempt secret"
    )


def test_reissuer_refuses_a_context_object_a_duck_and_wrong_types(env: Env) -> None:
    c, token, secret = env.start()

    class Duck:
        team, run, stage, visit, attempt = "alpha", c.run, "implement", 1, 1
        tools, repo, sha = c.tools, c.repo, c.sha

    for bad in (c, Duck(), None, 5, b"x", {"team": "alpha"}):
        assert reason(env.reissuer.reissue, bad, secret, now=NOW) == "malformed token"
    for bad_secret in (None, "s", 5, bytearray(secret)):
        assert reason(env.reissuer.reissue, token, bad_secret, now=NOW) == "bad attempt secret"
    for bad_now in ("x", None, 1.5, True):
        assert reason(env.reissuer.reissue, token, secret, now=bad_now) == "invalid now"


def test_reissuer_refuses_expired_forged_and_wrong_audience_tokens(env: Env) -> None:
    _, token, secret = env.start()
    assert reason(env.reissuer.reissue, token, secret, now=NOW + 300) == "expired"
    head, body, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["team"] = "beta"
    assert (
        reason(env.reissuer.reissue, swap_part(token, 1, dump(claims)), secret, now=NOW)
        == "bad signature"
    )
    foreign = mint_step_token(env.signer, ctx(), now=NOW, audience="gateway")
    assert reason(env.reissuer.reissue, foreign, secret, now=NOW) == "wrong audience"
    other_issuer = mint_step_token(env.signer, ctx(), now=NOW, issuer="x")
    assert reason(env.reissuer.reissue, other_issuer, secret, now=NOW) == "wrong issuer"


def test_reissuer_checks_liveness_itself_not_via_the_broker(env: Env) -> None:
    context, token, secret = env.start()
    env.directory.end(context)
    assert reason(env.reissuer.reissue, token, secret, now=NOW) == "step not live"
    unknown = mint_step_token(env.signer, ctx(stage="review"), now=NOW)
    assert reason(env.reissuer.reissue, unknown, secret, now=NOW) == "step not live"


def test_reissuer_refuses_a_directory_that_returns_something_else(env: Env) -> None:
    _, token, secret = env.start()

    class Fake:
        def attempt(self, context: StepContext) -> Any:
            return types.SimpleNamespace(
                live=True, deadline=NOW + 9999, secret_digest=hashlib.sha256(secret).digest(),
                context=context,
            )  # fmt: skip

    r = InProcessReissuer(env.signer, env.verifier, Fake())
    assert reason(r.reissue, token, secret, now=NOW) == "step not live"


def test_reissuer_refuses_to_return_a_token_if_the_step_ended_while_signing(env: Env) -> None:
    context, token, secret = env.start()

    class EndingSigner:
        algorithm = env.signer.algorithm
        key_id = env.signer.key_id

        def sign(self, message: bytes) -> Signature:
            env.directory.end(context)  # cancel arrives mid-signature
            return env.signer.sign(message)

        def verify(self, message: bytes, signature: Signature) -> bool:
            return env.signer.verify(message, signature)

        def public_keys(self) -> list[dict[str, str]]:
            return []

    r = InProcessReissuer(EndingSigner(), env.verifier, env.directory)
    assert reason(r.reissue, token, secret, now=NOW) == "step not live"


def test_broker_refuses_a_token_for_a_step_that_ended_during_reissue(env: Env) -> None:
    context, token, secret = env.start()

    class EndsThenReturns:
        ttl = 300

        def reissue(self, token: str, secret: bytes, *, now: int) -> str:
            new = env.reissuer.reissue(token, secret, now=now)
            env.directory.end(context)
            return new

    env.broker._reissuer = EndsThenReturns()  # noqa: SLF001
    assert reason(env.broker.refresh, token, secret, now=NOW) == "step not live"


def test_a_long_step_can_refresh_repeatedly_until_its_deadline(env: Env) -> None:
    context, token, secret = env.start(deadline=NOW + 1000)
    now = NOW
    while now + 250 < NOW + 1000:
        now += 250
        token = env.broker.refresh(token, secret, now=now)
    assert hs_verifier(env.signer).verify(token, now=now).context == context


def test_refresh_never_outlives_the_step_deadline(env: Env) -> None:
    _, token, secret = env.start(deadline=NOW + 400)
    new = env.broker.refresh(token, secret, now=NOW + 250)
    assert hs_verifier(env.signer).verify(new, now=NOW + 250).exp == NOW + 400
    assert reason(env.broker.refresh, new, secret, now=NOW + 400) == "expired"


def test_refresh_is_refused_for_an_ended_step(env: Env) -> None:
    context, token, secret = env.start()
    env.directory.end(context)
    assert reason(env.broker.refresh, token, secret, now=NOW + 10) == "step not live"


def test_refresh_is_refused_for_an_unknown_step(env: Env) -> None:
    token = mint_step_token(env.signer, ctx(), now=NOW)  # never registered
    assert reason(env.broker.refresh, token, new_attempt_secret(), now=NOW) == "step not live"


def test_reads_flags_and_refresh_all_stop_at_the_deadline(env: Env) -> None:
    run = ctx().run
    env.store.put(TeamScope("alpha"), Key(f"RUN#{run}", "TICKET#1"), {"t": 1})
    _, token, secret = env.start(deadline=NOW + 100)  # token itself lives to NOW + 300
    assert env.broker.read_ledger(token, "TICKET#1", now=NOW + 99) is not None
    env.broker.raise_flag(token, "n", "d", now=NOW + 99)
    for call in (
        lambda: env.broker.read_ledger(token, "TICKET#1", now=NOW + 100),
        lambda: env.broker.raise_flag(token, "n", "d", now=NOW + 100),
        lambda: env.broker.refresh(token, secret, now=NOW + 100),
    ):
        with pytest.raises(StepTokenError, match="step deadline passed"):
            call()
    assert len(env.flags.raised) == 1


def test_refresh_needs_the_attempt_secret(env: Env) -> None:
    _, token, secret = env.start()
    assert reason(env.broker.refresh, token, new_attempt_secret(), now=NOW) == "bad attempt secret"
    assert reason(env.broker.refresh, token, b"", now=NOW) == "bad attempt secret"
    assert reason(env.broker.refresh, token, secret[:-1], now=NOW) == "bad attempt secret"
    assert reason(env.broker.refresh, token, secret.hex(), now=NOW) == "bad attempt secret"


def test_the_secret_of_a_different_step_is_refused(env: Env) -> None:
    """Both steps are live; one step's secret does not refresh the other's token."""
    _, token, _ = env.start(ctx(stage="implement"))
    _, _, other_secret = env.start(ctx(stage="review"))
    assert reason(env.broker.refresh, token, other_secret, now=NOW) == "bad attempt secret"


def test_registering_attempt_2_supersedes_attempt_1(env: Env) -> None:
    run = ctx().run
    env.store.put(TeamScope("alpha"), Key(f"RUN#{run}", "TICKET#1"), {"t": 1})
    _, tok1, sec1 = env.start(ctx(attempt=1))
    assert env.broker.read_ledger(tok1, "TICKET#1", now=NOW) is not None
    _, tok2, sec2 = env.start(ctx(attempt=2))
    assert reason(env.broker.refresh, tok1, sec1, now=NOW) == "step not live"
    assert reason(env.broker.read_ledger, tok1, "TICKET#1", now=NOW) == "step not live"
    assert reason(env.broker.raise_flag, tok1, "n", "d", now=NOW) == "step not live"
    assert env.broker.read_ledger(tok2, "TICKET#1", now=NOW) is not None
    assert env.broker.refresh(tok2, sec2, now=NOW + 1)


def test_a_different_visit_is_a_different_step(env: Env) -> None:
    _, tok1, sec1 = env.start(ctx(visit=1, attempt=2))
    env.start(ctx(visit=2, attempt=1))
    assert env.broker.refresh(tok1, sec1, now=NOW + 1)


def test_end_of_attempt_2_before_it_registers_stops_attempt_1(env: Env) -> None:
    """A cancel for 2 arrives first: 2 can never register, and 1 must not run to its deadline."""
    run = ctx().run
    env.store.put(TeamScope("alpha"), Key(f"RUN#{run}", "TICKET#1"), {"t": 1})
    _, tok1, sec1 = env.start(ctx(attempt=1), deadline=NOW + 100_000)
    env.directory.end(ctx(attempt=2))
    with pytest.raises(StepTokenError, match="ended"):
        env.directory.register(ctx(attempt=2), new_attempt_secret(), deadline=NOW + 1000)
    assert reason(env.broker.refresh, tok1, sec1, now=NOW + 1) == "step not live"
    assert reason(env.broker.read_ledger, tok1, "TICKET#1", now=NOW + 1) == "step not live"
    assert reason(env.reissuer.reissue, tok1, sec1, now=NOW + 1) == "step not live"


def test_end_does_not_block_a_later_attempt(env: Env) -> None:
    env.directory.end(ctx(attempt=2))
    _, tok3, sec3 = env.start(ctx(attempt=3))
    assert env.broker.refresh(tok3, sec3, now=NOW + 1)


def test_end_of_a_lower_attempt_does_not_lower_the_latest(env: Env) -> None:
    _, tok3, sec3 = env.start(ctx(attempt=3))
    env.directory.end(ctx(attempt=1))
    assert env.broker.refresh(tok3, sec3, now=NOW + 1)


@pytest.mark.parametrize(
    "other", [{"run": "OTHERRUN"}, {"stage": "review"}, {"team": "beta"}, {"visit": 2}]
)
def test_attempts_of_different_steps_do_not_supersede_each_other(
    env: Env, other: dict[str, Any]
) -> None:
    _, tok1, sec1 = env.start(ctx(attempt=1))
    env.start(ctx(attempt=2, **other))
    assert env.broker.refresh(tok1, sec1, now=NOW + 1)
    env.directory.end(ctx(attempt=5, **other))
    assert env.broker.refresh(tok1, sec1, now=NOW + 2)


class HookedLatest(dict[Any, int]):
    """A ``_latest`` map that runs a callback the first time it is read."""

    def __init__(self) -> None:
        super().__init__()
        self.hook: Any = None

    def get(self, key: Any, default: Any = None) -> Any:
        hook, self.hook = self.hook, None
        if hook is not None:
            hook()
        return super().get(key, default)


def test_concurrent_register_never_moves_the_latest_attempt_backwards(env: Env) -> None:
    """Force register(3) to run between register(2)'s check and its write."""
    latest = HookedLatest()
    env.directory._latest = latest  # noqa: SLF001
    done = threading.Event()

    def register_three() -> None:
        env.directory.register(ctx(attempt=3), new_attempt_secret(), deadline=NOW + 1000)
        done.set()

    def hook() -> None:
        threading.Thread(target=register_three, daemon=True).start()
        done.wait(timeout=0.3)  # without a lock this finishes here; with one it waits its turn

    latest.hook = hook
    env.directory.register(ctx(attempt=2), new_attempt_secret(), deadline=NOW + 1000)
    assert done.wait(timeout=5)
    three = env.directory.attempt(ctx(attempt=3))
    two = env.directory.attempt(ctx(attempt=2))
    assert three is not None
    assert three.live is True
    assert two is not None
    assert two.live is False


def test_an_ended_attempt_cannot_be_registered_again(env: Env) -> None:
    c = ctx()
    env.start(c)
    env.directory.end(c)
    with pytest.raises(StepTokenError, match="ended"):
        env.directory.register(c, new_attempt_secret(), deadline=NOW + 1000)
    record = env.directory.attempt(c)
    assert record is not None
    assert record.live is False


def test_end_before_register_sticks(env: Env) -> None:
    c = ctx()
    env.directory.end(c)
    with pytest.raises(StepTokenError, match="ended"):
        env.directory.register(c, new_attempt_secret(), deadline=NOW + 1000)
    assert env.directory.attempt(c) is None


def test_lower_or_duplicate_attempts_cannot_be_registered(env: Env) -> None:
    env.start(ctx(attempt=2))
    with pytest.raises(StepTokenError, match="superseded"):
        env.directory.register(ctx(attempt=1), new_attempt_secret(), deadline=NOW + 1000)
    with pytest.raises(StepTokenError, match="already registered"):
        env.directory.register(ctx(attempt=2), new_attempt_secret(), deadline=NOW + 1000)


def test_ending_the_current_attempt_does_not_revive_a_lower_one(env: Env) -> None:
    _, tok1, sec1 = env.start(ctx(attempt=1))
    c2, _, _ = env.start(ctx(attempt=2))
    env.directory.end(c2)
    assert reason(env.broker.refresh, tok1, sec1, now=NOW) == "step not live"


def test_refresh_refuses_expired_tampered_and_wrong_alg_tokens(env: Env) -> None:
    _, token, secret = env.start()
    assert reason(env.broker.refresh, token, secret, now=NOW + 300) == "expired"
    head, body, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["tools"] = ["repo.read", "repo.write"]
    forged = swap_part(token, 1, dump(claims))
    assert reason(env.broker.refresh, forged, secret, now=NOW) == "bad signature"
    none = f"{b64(dump({'alg': 'none', 'kid': 'step-1', 'typ': 'JWT'}))}.{body}."
    assert reason(env.broker.refresh, none, secret, now=NOW) == "algorithm not allowed"


def test_refresh_cannot_widen_scope(env: Env) -> None:
    """Nothing in the refresh path takes a claim; stage, tools, repo and SHA come from the token."""
    assert list(inspect.signature(StepBroker.refresh).parameters) == [
        "self",
        "token",
        "secret",
        "now",
    ]
    context, token, secret = env.start(ctx(tools=("repo.read",)))
    again = env.broker.refresh(
        env.broker.refresh(token, secret, now=NOW + 100), secret, now=NOW + 200
    )
    got = hs_verifier(env.signer).verify(again, now=NOW + 201).context
    assert got == context
    assert got.tools == ("repo.read",)


def test_a_valid_token_for_an_unregistered_attempt_is_not_live(env: Env) -> None:
    env.start(ctx(attempt=1))
    other = mint_step_token(env.signer, ctx(visit=2), now=NOW)
    assert reason(env.broker.refresh, other, new_attempt_secret(), now=NOW) == "step not live"


def test_ledger_read_is_scoped_to_the_tokens_team_and_run(env: Env) -> None:
    run = ctx().run
    env.store.put(TeamScope("alpha"), Key(f"RUN#{run}", "TICKET#1"), {"text": "alpha ticket"})
    env.store.put(TeamScope("beta"), Key(f"RUN#{run}", "TICKET#1"), {"text": "beta ticket"})
    _, token, _ = env.start()
    item = env.broker.read_ledger(token, "TICKET#1", now=NOW)
    assert item is not None
    assert item.data == {"text": "alpha ticket"}

    beta_ctx, beta_token, _ = env.start(ctx(team="beta"))
    beta = env.broker.read_ledger(beta_token, "TICKET#1", now=NOW)
    assert beta is not None
    assert beta.data == {"text": "beta ticket"}
    assert beta_ctx.team == "beta"


def test_a_session_cannot_read_another_teams_ledger(env: Env) -> None:
    run = ctx().run
    env.store.put(TeamScope("beta"), Key(f"RUN#{run}", "TICKET#1"), {"text": "beta secret"})
    _, token, _ = env.start()  # team alpha
    assert env.broker.read_ledger(token, "TICKET#1", now=NOW) is None


def test_a_session_cannot_read_another_run_in_its_own_team(env: Env) -> None:
    env.store.put(TeamScope("alpha"), Key("RUN#OTHER", "TICKET#1"), {"text": "other run"})
    _, token, _ = env.start()
    assert env.broker.read_ledger(token, "TICKET#1", now=NOW) is None


def test_token_cannot_be_retargeted_by_editing_team(env: Env) -> None:
    run = ctx().run
    env.store.put(TeamScope("beta"), Key(f"RUN#{run}", "TICKET#1"), {"text": "beta secret"})
    _, token, _ = env.start()
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    claims["team"] = "beta"
    forged = swap_part(token, 1, dump(claims))
    assert reason(env.broker.read_ledger, forged, "TICKET#1", now=NOW) == "bad signature"


@pytest.mark.parametrize(
    "sk",
    ["TOK#1", "META", "CHAIN", "FX#1", "OUT#1", "BUD#2026-11", "", "TICKET#1\nTOK#1"],
)
def test_ledger_read_is_limited_to_agent_readable_rows(env: Env, sk: str) -> None:
    run = ctx().run
    env.store.put(TeamScope("alpha"), Key(f"RUN#{run}", "TOK#1"), {"token": "secret"})
    _, token, _ = env.start()
    assert reason(env.broker.read_ledger, token, sk, now=NOW) == "ledger row not readable"


def test_another_attempts_step_row_is_not_readable(env: Env) -> None:
    run = ctx().run
    env.store.put(
        TeamScope("alpha"), Key(f"RUN#{run}", "STEP#3#2"), {"fence": 9, "session_id": "s"}
    )
    _, token, _ = env.start()
    assert reason(env.broker.read_ledger, token, "STEP#3#2", now=NOW) == "ledger row not readable"


def test_ledger_sort_key_length_limit(env: Env) -> None:
    _, token, _ = env.start()
    at_limit = "TICKET#" + "x" * (MAX_SK_LEN - len("TICKET#"))
    assert env.broker.read_ledger(token, at_limit, now=NOW) is None
    assert (
        reason(env.broker.read_ledger, token, at_limit + "x", now=NOW) == "ledger row not readable"
    )


def test_ledger_and_flags_are_refused_for_an_ended_step(env: Env) -> None:
    context, token, _ = env.start()
    env.directory.end(context)
    assert reason(env.broker.read_ledger, token, "TICKET#1", now=NOW) == "step not live"
    assert reason(env.broker.raise_flag, token, "scope_creep", "x", now=NOW) == "step not live"
    assert env.flags.raised == []


def test_flag_identity_comes_from_the_token(env: Env) -> None:
    context, token, _ = env.start()
    env.broker.raise_flag(token, "scope_creep", "touches infra/", now=NOW)
    assert env.flags.raised == [(context, "scope_creep", "touches infra/")]


def test_flag_input_is_validated(env: Env) -> None:
    _, token, _ = env.start()
    for name, detail in (("", "x"), ("a\nb", "x"), ("n", "x" * 5000), ("n" * 200, "x")):
        assert reason(env.broker.raise_flag, token, name, detail, now=NOW) == "invalid flag"
    assert env.flags.raised == []


def test_broker_calls_refuse_expired_and_wrong_alg_tokens(env: Env) -> None:
    _, token, _ = env.start()
    assert reason(env.broker.read_ledger, token, "TICKET#1", now=NOW + 300) == "expired"
    assert reason(env.broker.raise_flag, token, "n", "d", now=NOW + 300) == "expired"


# -- failing dependencies fail closed -----------------------------------------------------------


class Boom(Exception):
    pass


def test_store_failure_propagates(env: Env) -> None:
    class BadStore(MemoryStore):
        def get(self, scope: Any, key: Any) -> Any:
            raise TransientError("store down")

    env.broker._store = BadStore()  # noqa: SLF001
    _, token, _ = env.start()
    with pytest.raises(TransientError):
        env.broker.read_ledger(token, "TICKET#1", now=NOW)


def test_directory_failure_means_no_access_and_no_refresh(env: Env) -> None:
    _, token, secret = env.start()

    class BadDirectory:
        def attempt(self, context: StepContext) -> AttemptRecord | None:
            raise TransientError("directory down")

    env.broker._directory = BadDirectory()  # noqa: SLF001
    for call in (
        lambda: env.broker.read_ledger(token, "TICKET#1", now=NOW),
        lambda: env.broker.raise_flag(token, "n", "d", now=NOW),
        lambda: env.broker.refresh(token, secret, now=NOW),
    ):
        with pytest.raises(TransientError):
            call()
    assert env.flags.raised == []


def test_flag_sink_failure_propagates(env: Env) -> None:
    class BadFlags:
        def raise_flag(self, context: StepContext, name: str, detail: str) -> None:
            raise Boom

    env.broker._flags = BadFlags()  # noqa: SLF001
    _, token, _ = env.start()
    with pytest.raises(Boom):
        env.broker.raise_flag(token, "n", "d", now=NOW)


def test_signer_failure_during_refresh_stays_transient_and_returns_no_token(env: Env) -> None:
    class DownSigner:
        algorithm = "HS256"
        key_id = "step-1"

        def sign(self, message: bytes) -> Signature:
            raise TransientError("kms throttle")

        def verify(self, message: bytes, signature: Signature) -> bool:
            return False

        def public_keys(self) -> list[dict[str, str]]:
            return []

    env.broker._reissuer = InProcessReissuer(  # noqa: SLF001
        DownSigner(), env.verifier, env.directory
    )
    _, token, secret = env.start()
    with pytest.raises(TransientError):
        env.broker.refresh(token, secret, now=NOW)


def test_reissuer_returning_garbage_is_refused(env: Env) -> None:
    class Garbage:
        ttl = 300

        def reissue(self, token: str, secret: bytes, *, now: int) -> str:
            return "not.a.token"

    env.broker._reissuer = Garbage()  # noqa: SLF001
    _, token, secret = env.start()
    assert reason(env.broker.refresh, token, secret, now=NOW) == "malformed token"


def test_signature_with_altered_trailing_bits_is_refused(hs: LocalSigner) -> None:
    """HMAC-SHA256 is 32 bytes = 43 base64url chars; the last char has 2 spare bits. A char that
    decodes to the same bytes would be a second valid spelling of one signature (malleability)."""
    token = mint_step_token(hs, ctx(), now=NOW)
    head, body, sig = token.split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    twin = next(
        c
        for c in alphabet
        if c != sig[-1] and alphabet.index(c) >> 2 == alphabet.index(sig[-1]) >> 2
    )
    assert base64.urlsafe_b64decode(sig + "=") == base64.urlsafe_b64decode(sig[:-1] + twin + "=")
    assert (
        reason(hs_verifier(hs).verify, f"{head}.{body}.{sig[:-1]}{twin}", now=NOW)
        == "malformed token"
    )


def test_jwks_verifier_only_answers_for_rs256(rsa_signer: RsaSigner) -> None:
    jwks = JwksVerifier({"keys": rsa_signer.public_keys()})
    msg = b"m"
    good = rsa_signer.sign(msg)
    assert jwks.verify(msg, good) is True
    other_alg = Signature(key_id=good.key_id, algorithm="HS256", value=good.value)
    assert jwks.verify(msg, other_alg) is False
    assert jwks.verify(b"other", good) is False


def test_jwks_refuses_duplicate_key_ids(rsa_signer: RsaSigner) -> None:
    good = rsa_signer.public_keys()[0]
    with pytest.raises(SigningError):
        JwksVerifier({"keys": [good, good]})
