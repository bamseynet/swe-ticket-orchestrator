"""Signed step context (D5-19, PLAN 8.3).

The dispatcher mints a short-lived JWT per step. It names the step (team, run, stage, visit,
attempt) and what the step may use (tools, repo, SHA). Cedar and the tool layer read these claims,
so a model can never choose its own repo or team.

Verification fails closed. Every refusal raises ``StepTokenError`` with a stable ``reason``:

* The algorithm is **pinned by the verifier**, never read from the token. A header that says
  ``none``, or the other family (an ``HS256`` token signed with a published RSA key, the
  key-confusion attack), is refused before any key is touched. The signature is then checked
  as the pinned algorithm.
* The header holds exactly ``alg``, ``kid``, ``typ``; ``jku``, ``jwk``, ``crit`` etc. are refused.
* The payload holds exactly the claims below, each with its exact type. ``iss`` and ``aud`` must
  equal what the verifier was built for (``aud`` is a single string, not a list). A missing,
  extra or mistyped claim refuses the token.
* Time is passed in (``now``, whole seconds) so there is no hidden clock. ``leeway`` is capped at
  ``MAX_LEEWAY`` seconds, and the lifetime ``exp - iat`` is capped at ``max_ttl``, so a mistaken
  signer cannot mint a long-lived token.
* Expiry beats stage: an expired token is reported as expired even for the wrong stage.

Verifying needs only a ``Verifier`` (the signer port without ``sign``). ``JwksVerifier`` builds one
from a JWKS document, so a broker or the Gateway holds public keys only. The AWS issuer is D11-23.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from sto.domain.errors import PermanentError
from sto.signing.port import Signature, Signer, SigningError, Verifier

ISSUER: Final = "sto-dispatcher"
AUDIENCE: Final = "sto-step-context"
ALGORITHMS: Final = ("HS256", "RS256")
DEFAULT_TTL: Final = 300
MAX_TTL: Final = 900
MAX_LEEWAY: Final = 60
MAX_TOKEN_BYTES: Final = 8 * 1024
MAX_TOOLS: Final = 64
MAX_TOOL_NAME: Final = 128
MAX_JTI: Final = 64
MIN_RSA_BITS: Final = 2048
MAX_RSA_BITS: Final = 8192
MIN_RSA_EXPONENT: Final = 65537
# Private RSA/symmetric members (RFC 7517/7518). A document holding any of them is refused whole.
PRIVATE_JWK_MEMBERS: Final = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
# Only these members are kept on load and returned by ``public_keys``.
PUBLIC_JWK_MEMBERS: Final = ("kid", "kty", "alg", "use", "n", "e")

_HEADER_KEYS = frozenset({"alg", "kid", "typ"})
_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "team",
        "run",
        "stage",
        "visit",
        "attempt",
        "tools",
        "repo",
        "sha",
        "iat",
        "nbf",
        "exp",
        "jti",
    }  # fmt: skip
)
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class StepTokenError(PermanentError):
    """A token was refused. ``reason`` is a stable code; the message never holds token text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _bad(reason: str) -> StepTokenError:
    return StepTokenError(reason)


@dataclass(frozen=True)
class StepContext:
    """What the step is and may use. Fixed for the life of the step, across refreshes."""

    team: str
    run: str
    stage: str
    visit: int
    attempt: int
    tools: tuple[str, ...]
    repo: str
    sha: str

    def __post_init__(self) -> None:
        for name in ("team", "run", "stage", "repo"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or value != value.strip():
                raise _bad(f"invalid {name}")
            if not value.isprintable():
                raise _bad(f"invalid {name}")
        if "#" in self.team:  # a key separator in the store; keep it out of identities
            raise _bad("invalid team")
        for name in ("visit", "attempt"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise _bad(f"invalid {name}")
        if not isinstance(self.sha, str) or not _SHA.fullmatch(self.sha):
            raise _bad("invalid sha")
        if (
            not isinstance(self.tools, tuple)
            or len(self.tools) > MAX_TOOLS
            or any(
                not isinstance(t, str)
                or not t
                or len(t) > MAX_TOOL_NAME
                or t != t.strip()
                or not t.isprintable()
                for t in self.tools
            )
            or len(set(self.tools)) != len(self.tools)
        ):
            raise _bad("invalid tools")


@dataclass(frozen=True)
class StepToken:
    """A verified token's claims."""

    context: StepContext
    iat: int
    nbf: int
    exp: int
    jti: str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    if not _B64URL.fullmatch(text):
        raise _bad("malformed token")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise _bad("malformed token") from exc
    if _b64(raw) != text:  # refuse non-canonical trailing bits
        raise _bad("malformed token")
    return raw


def _json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out

    def no_constant(_: str) -> Any:
        raise ValueError("non-finite number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=no_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        # ``from None``: ``__cause__`` of a JSONDecodeError holds the decoded payload text.
        raise _bad("malformed token") from None
    if not isinstance(value, dict):
        raise _bad("malformed token")
    return value


def _dump(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def mint_step_token(
    signer: Signer,
    context: StepContext,
    *,
    now: int,
    ttl: int = DEFAULT_TTL,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
) -> str:
    """Sign a token for ``context`` valid for ``ttl`` seconds from ``now`` (<= ``MAX_TTL``)."""
    if type(now) is not int or now < 0:
        raise _bad("invalid now")
    if type(ttl) is not int or not 0 < ttl <= MAX_TTL:
        raise _bad("invalid ttl")
    if signer.algorithm not in ALGORITHMS:
        raise _bad("unsupported algorithm")
    header = {"alg": signer.algorithm, "kid": signer.key_id, "typ": "JWT"}
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "team": context.team,
        "run": context.run,
        "stage": context.stage,
        "visit": context.visit,
        "attempt": context.attempt,
        "tools": list(context.tools),
        "repo": context.repo,
        "sha": context.sha,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(16),
    }
    signing_input = f"{_b64(_dump(header))}.{_b64(_dump(claims))}"
    sig = signer.sign(signing_input.encode("ascii"))
    if sig.algorithm != signer.algorithm or sig.key_id != signer.key_id:
        raise _bad("signer returned an inconsistent signature")
    token = f"{signing_input}.{_b64(sig.value)}"
    if len(token) > MAX_TOKEN_BYTES:
        raise _bad("token too large")
    return token


class StepTokenVerifier:
    """Checks tokens against one pinned algorithm, issuer and audience."""

    __slots__ = ("_algorithm", "_audience", "_issuer", "_leeway", "_max_ttl", "_verifier")

    @property
    def max_ttl(self) -> int:
        return self._max_ttl

    def __init__(
        self,
        verifier: Verifier,
        *,
        algorithm: str,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        leeway: int = 0,
        max_ttl: int = MAX_TTL,
    ) -> None:
        if algorithm not in ALGORITHMS:
            raise _bad("unsupported algorithm")
        if type(leeway) is not int or not 0 <= leeway <= MAX_LEEWAY:
            raise _bad("invalid leeway")
        if type(max_ttl) is not int or not 0 < max_ttl <= MAX_TTL:
            raise _bad("invalid max_ttl")
        if not issuer or not audience:
            raise _bad("issuer and audience are required")
        self._verifier = verifier
        self._algorithm = algorithm
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway
        self._max_ttl = max_ttl

    def verify(self, token: str, *, now: int, stage: str | None = None) -> StepToken:
        """Return the claims, or raise ``StepTokenError``. ``stage`` must match when given."""
        if type(now) is not int:
            raise _bad("invalid now")
        if not isinstance(token, str) or not token.isascii() or len(token) > MAX_TOKEN_BYTES:
            raise _bad("malformed token")
        parts = token.split(".")
        if len(parts) != 3:
            raise _bad("malformed token")
        head_b64, body_b64, sig_b64 = parts
        header = _json(_unb64(head_b64))
        claims = _json(_unb64(body_b64))

        if set(header) != _HEADER_KEYS or header["typ"] != "JWT":
            raise _bad("bad header")
        if header["alg"] != self._algorithm:  # covers "none", the other family, and junk
            raise _bad("algorithm not allowed")
        raw_sig = _unb64(sig_b64)
        kid = header["kid"]
        if not isinstance(kid, str) or not kid or not kid.isprintable():
            raise _bad("bad header")
        try:
            signature = Signature(key_id=kid, algorithm=self._algorithm, value=raw_sig)
            ok = self._verifier.verify(f"{head_b64}.{body_b64}".encode("ascii"), signature)
        except SigningError as exc:
            raise _bad("bad signature") from exc
        if ok is not True:
            raise _bad("bad signature")

        return self._check_claims(claims, now=now, stage=stage)

    def _check_claims(self, claims: dict[str, Any], *, now: int, stage: str | None) -> StepToken:
        if set(claims) != _CLAIMS:
            raise _bad("bad claims")
        if claims["iss"] != self._issuer:
            raise _bad("wrong issuer")
        aud = claims["aud"]
        if not isinstance(aud, str) or aud != self._audience:
            raise _bad("wrong audience")
        times = {}
        for name in ("iat", "nbf", "exp"):
            value = claims[name]
            if type(value) is not int or value < 0:
                raise _bad("bad claims")
            times[name] = value
        iat, nbf, exp = times["iat"], times["nbf"], times["exp"]
        jti = claims["jti"]
        if (
            not isinstance(jti, str)
            or not jti
            or len(jti) > MAX_JTI
            or not jti.isascii()
            or not jti.isprintable()
        ):
            raise _bad("bad claims")
        if not iat <= nbf < exp or exp - iat > self._max_ttl:
            raise _bad("bad lifetime")
        if now >= exp + self._leeway:
            raise _bad("expired")
        if now < nbf - self._leeway:  # nbf >= iat, so this also covers iat
            raise _bad("not yet valid")
        tools = claims["tools"]
        if not isinstance(tools, list):
            raise _bad("bad claims")
        try:
            context = StepContext(
                team=claims["team"],
                run=claims["run"],
                stage=claims["stage"],
                visit=claims["visit"],
                attempt=claims["attempt"],
                tools=tuple(tools),
                repo=claims["repo"],
                sha=claims["sha"],
            )
        except StepTokenError as exc:
            raise _bad("bad claims") from exc
        if stage is not None and context.stage != stage:
            raise _bad("wrong stage")
        return StepToken(context=context, iat=iat, nbf=nbf, exp=exp, jti=jti)


def _int_from_b64(text: object) -> int:
    if not isinstance(text, str) or not text or not _B64URL.fullmatch(text):
        raise SigningError("invalid JWKS key")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise SigningError("invalid JWKS key") from None
    return int.from_bytes(raw, "big")


def _public_jwk(jwk: Mapping[str, Any]) -> dict[str, str]:
    """Validate one JWK and return only its allow-listed public members."""
    if PRIVATE_JWK_MEMBERS & set(jwk):
        raise SigningError("JWKS must not contain private key material")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid or not kid.isprintable():
        raise SigningError("invalid JWKS key")
    if jwk.get("kty") != "RSA" or jwk.get("alg") != "RS256":
        raise SigningError("invalid JWKS key")
    if "use" in jwk and jwk["use"] != "sig":
        raise SigningError("invalid JWKS key")
    if "key_ops" in jwk:
        ops = jwk["key_ops"]
        if not isinstance(ops, list) or "verify" not in ops:
            raise SigningError("invalid JWKS key")
    out = {name: jwk[name] for name in PUBLIC_JWK_MEMBERS if name in jwk}
    if any(not isinstance(v, str) for v in out.values()):
        raise SigningError("invalid JWKS key")
    return out


class JwksVerifier:
    """A ``Verifier`` built from a JWKS document: RSA public keys only, ``RS256`` only.

    Holds no signing power. A bad document fails at load, not when a token arrives: any private
    member, a ``use`` other than ``sig``, ``key_ops`` without ``verify``, a non-printable or
    repeated ``kid``, a modulus that is even or outside 2048..8192 bits, or an exponent below
    65537. Members outside ``PUBLIC_JWK_MEMBERS`` (``x5u``, ``jku``, ...) are dropped, so
    ``public_keys`` returns nothing the document did not need to publish.
    """

    __slots__ = ("_keys",)

    def __init__(self, jwks: Mapping[str, Any]) -> None:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        raw = jwks.get("keys") if isinstance(jwks, Mapping) else None
        if not isinstance(raw, Sequence) or isinstance(raw, str) or not raw:
            raise SigningError("JWKS must hold a non-empty keys array")
        keys: dict[str, Any] = {}
        for jwk in raw:
            if not isinstance(jwk, Mapping):
                raise SigningError("invalid JWKS key")
            public = _public_jwk(jwk)
            kid = public["kid"]
            if kid in keys:
                raise SigningError("invalid JWKS key")
            n, e = _int_from_b64(public.get("n")), _int_from_b64(public.get("e"))
            if not MIN_RSA_BITS <= n.bit_length() <= MAX_RSA_BITS or n % 2 == 0:
                raise SigningError("invalid JWKS key")
            if e < MIN_RSA_EXPONENT or e % 2 == 0 or e >= n:
                raise SigningError("invalid JWKS key")
            try:
                keys[kid] = (RSAPublicNumbers(e, n).public_key(), public)
            except ValueError:
                raise SigningError("invalid JWKS key") from None
        self._keys = keys

    def verify(self, message: bytes, signature: Signature) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        if not isinstance(message, bytes) or not isinstance(signature, Signature):
            raise SigningError("verify needs bytes and a Signature")
        entry = self._keys.get(signature.key_id)
        if entry is None or signature.algorithm != "RS256":
            return False
        try:
            entry[0].verify(signature.value, message, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return False
        return True

    def public_keys(self) -> Sequence[Mapping[str, str]]:
        return tuple(dict(public) for _, public in self._keys.values())


class StepReissuer(Protocol):
    """The dispatcher's side of a refresh. The broker holds this, never a ``Signer``.

    ``reissue`` takes only a verified context: it accepts no claim to change, so a refresh cannot
    widen stage, tools, repo or SHA. The dispatcher clamps the new expiry to the attempt's deadline
    and refuses a step that is not live. ``ttl`` is the lifetime it asks for before clamping.
    """

    @property
    def ttl(self) -> int: ...

    def reissue(self, context: StepContext, *, now: int) -> str: ...


class InProcessReissuer:
    """``StepReissuer`` for one host and for tests. A deployed broker calls the dispatcher instead.

    ``deadline_of`` answers for a context with the attempt's deadline, or ``None`` if the attempt
    is not live. It is the dispatcher's own record, not the broker's.
    """

    __slots__ = ("_audience", "_deadline_of", "_issuer", "_signer", "_ttl")

    def __init__(
        self,
        signer: Signer,
        deadline_of: Callable[[StepContext], int | None],
        *,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        ttl: int = DEFAULT_TTL,
    ) -> None:
        if type(ttl) is not int or not 0 < ttl <= MAX_TTL:
            raise _bad("invalid ttl")
        self._signer = signer
        self._deadline_of = deadline_of
        self._issuer = issuer
        self._audience = audience
        self._ttl = ttl

    @property
    def ttl(self) -> int:
        return self._ttl

    def reissue(self, context: StepContext, *, now: int) -> str:
        deadline = self._deadline_of(context)
        if type(deadline) is not int:
            raise _bad("step not live")
        if now >= deadline:
            raise _bad("step deadline passed")
        return mint_step_token(
            self._signer,
            context,
            now=now,
            ttl=min(self._ttl, deadline - now),
            issuer=self._issuer,
            audience=self._audience,
        )
