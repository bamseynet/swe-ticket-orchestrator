"""Signed step context (D5-19): token verification fails closed, and the broker enforces scope."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sto.agents.step_token import (
    AUDIENCE,
    ISSUER,
    MAX_LEEWAY,
    MAX_TTL,
    JwksVerifier,
    StepContext,
    StepTokenError,
    StepTokenVerifier,
    mint_step_token,
)
from sto.budget.broker import (
    AttemptDirectory,
    InMemoryAttemptDirectory,
    StepBroker,
    new_attempt_secret,
)
from sto.signing.local import LocalSigner
from sto.signing.port import Signature, SigningError
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

    def __init__(self, key_id: str = "rsa-1") -> None:
        self.key_id = key_id
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

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


def test_signature_is_checked_as_the_pinned_algorithm(rsa_signer: RsaSigner) -> None:
    """Even a verifier that would accept HS256 signatures is asked only about the pinned one."""
    seen: list[str] = []

    class Spy:
        def verify(self, message: bytes, signature: Signature) -> bool:
            seen.append(signature.algorithm)
            return True

        def public_keys(self) -> list[dict[str, str]]:
            return []

    token = mint_step_token(rsa_signer, ctx(), now=NOW)
    StepTokenVerifier(Spy(), algorithm="RS256").verify(token, now=NOW)
    assert seen == ["RS256"]


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
        {"keys": [{**good, "d": "AA"}]},
        {"keys": [{**good, "n": b64(b"\x01" * 64)}]},  # 512-bit modulus
        {"keys": [{**good, "n": "!!"}]},
        {"keys": [{**good, "e": b64(b"\x02")}]},
    ]
    for doc in docs:
        with pytest.raises(SigningError):
            JwksVerifier(doc)


# -- broker -------------------------------------------------------------------------------------


class Flags:
    def __init__(self) -> None:
        self.raised: list[tuple[StepContext, str, str]] = []

    def raise_flag(self, context: StepContext, name: str, detail: str) -> None:
        self.raised.append((context, name, detail))


class Env:
    def __init__(self, signer: LocalSigner) -> None:
        self.signer = signer
        self.store = MemoryStore()
        self.directory = InMemoryAttemptDirectory()
        self.flags = Flags()
        self.broker = StepBroker(
            signer=signer,
            verifier=hs_verifier(signer),
            directory=self.directory,
            store=self.store,
            flags=self.flags,
        )

    def start(
        self, context: StepContext | None = None, *, deadline: int = NOW + 7200
    ) -> tuple[StepContext, str, bytes]:
        context = context or ctx()
        secret = new_attempt_secret()
        self.directory.register(context, secret, deadline=deadline)
        return context, mint_step_token(self.signer, context, now=NOW), secret


@pytest.fixture
def env(hs: LocalSigner) -> Env:
    return Env(hs)


def test_attempt_secret_is_long_and_random() -> None:
    assert len(new_attempt_secret()) >= 32
    assert new_attempt_secret() != new_attempt_secret()


def test_directory_stores_a_digest_not_the_secret(env: Env) -> None:
    context, _, secret = env.start()
    record = env.directory.attempt(context)
    assert record is not None
    assert record.secret_digest == hashlib.sha256(secret).digest()
    assert secret not in repr(record).encode()
    assert isinstance(env.directory, AttemptDirectory)


def test_refresh_issues_a_new_token_with_identical_claims(env: Env) -> None:
    context, token, secret = env.start()
    new = env.broker.refresh(token, secret, now=NOW + 200)
    assert new != token
    got = hs_verifier(env.signer).verify(new, now=NOW + 201)
    assert got.context == context
    assert got.exp == NOW + 200 + 300
    assert got.jti != hs_verifier(env.signer).verify(token, now=NOW + 1).jti


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
    assert reason(env.broker.refresh, new, secret, now=NOW + 400) in {
        "expired",
        "step deadline passed",
    }


def test_refresh_is_refused_for_an_ended_step(env: Env) -> None:
    context, token, secret = env.start()
    env.directory.end(context)
    assert reason(env.broker.refresh, token, secret, now=NOW + 10) == "step not live"


def test_refresh_is_refused_for_an_unknown_step(env: Env) -> None:
    token = mint_step_token(env.signer, ctx(), now=NOW)  # never registered
    assert reason(env.broker.refresh, token, new_attempt_secret(), now=NOW) == "step not live"


def test_refresh_is_refused_after_the_deadline_even_if_marked_live(env: Env) -> None:
    _, token, secret = env.start(deadline=NOW + 100)
    assert reason(env.broker.refresh, token, secret, now=NOW + 100) in {
        "expired",
        "step deadline passed",
    }


def test_refresh_needs_the_attempt_secret(env: Env) -> None:
    _, token, secret = env.start()
    assert reason(env.broker.refresh, token, new_attempt_secret(), now=NOW) == "bad attempt secret"
    assert reason(env.broker.refresh, token, b"", now=NOW) == "bad attempt secret"
    assert reason(env.broker.refresh, token, secret[:-1], now=NOW) == "bad attempt secret"


def test_refresh_secret_of_another_attempt_is_refused(env: Env) -> None:
    """(step, attempt) is guessable; the secret is not."""
    _, token, _ = env.start(ctx(attempt=1))
    _, _, other_secret = env.start(ctx(attempt=2))
    assert reason(env.broker.refresh, token, other_secret, now=NOW) == "bad attempt secret"


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
    """The broker takes no claims to change; stage, tools, repo and SHA come from the old token."""
    import inspect

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


def test_refresh_ignores_a_token_whose_context_differs_from_the_registered_attempt(
    env: Env,
) -> None:
    """A valid token for attempt 2 does not become live because attempt 1 is."""
    env.start(ctx(attempt=1))
    other = mint_step_token(env.signer, ctx(attempt=2), now=NOW)
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


@pytest.mark.parametrize("sk", ["TOK#1", "META", "CHAIN", "FX#1", "OUT#1", "", "TICKET#1\nTOK#1"])
def test_ledger_read_is_limited_to_agent_readable_rows(env: Env, sk: str) -> None:
    run = ctx().run
    env.store.put(TeamScope("alpha"), Key(f"RUN#{run}", "TOK#1"), {"token": "secret"})
    _, token, _ = env.start()
    assert reason(env.broker.read_ledger, token, sk, now=NOW) == "ledger row not readable"


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
