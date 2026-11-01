"""OIDC token validation by issuer plus JWKS (PLAN 9.2, ADR-0008).

The API trusts *an issuer and its keys*, not a particular vendor. Everything that differs for
Cognito is a value in :class:`OidcConfig`, built by :func:`cognito_config`; the validator has no
vendor branches, so another broker can replace Cognito by changing config.

Refusals (:class:`InvalidTokenError`, permanent, with a stable ``reason``): malformed token
(including non-UTF-8 payloads, duplicate keys, NaN/Infinity and over-deep nesting), algorithm
outside the allow-list (so ``none`` and HMAC-with-public-key confusion are out), unknown ``kid``,
bad signature, wrong issuer, wrong audience, expired or not-yet-valid (``exp`` is exclusive), a
future ``auth_time``, missing ``sub`` or ``exp``, and a wrong ``token_use`` when one is required.

Failure classes. A JWKS that cannot be fetched is :class:`~sto.domain.errors.TransientError`,
never "invalid token": that includes an unknown ``kid`` while the last refresh failed (the IdP may
have rotated), a cold start with no keys, and keys older than ``max_stale_seconds`` (6 hours by
default). Cached keys keep verifying through a shorter outage. A 200 response that lists keys but
yields no usable ones counts as a failed refresh and never replaces the cached set.

Decisions:

* ``aud`` may be a list of strings; any other audience claim (Cognito ``client_id``) must be a
  single string. ``azp`` is deliberately NOT enforced: resource-bound access tokens (for example
  Keycloak's) carry the client in ``azp``, not the audience, and OIDC only says SHOULD.
* RSA keys must have an odd modulus of 2048 to 8192 bits and an exponent of at least 65537. EC
  keys must be P-256 points on the curve. JWKS entries with private parameters, a non-``verify``
  ``key_ops``, ``use`` other than ``sig``, or a duplicated ``kid`` (both are dropped) are ignored.
  A key whose own ``alg`` differs from the token's header ``alg`` is refused.
* Cold-start fetches are rate limited like any other. With a healthy cold start, concurrent
  requests may each fetch once (no lock, accepted); the cache dict is swapped whole.
* Cache timing (TTL, rate limit, staleness) uses a monotonic clock; token claims use wall time.

Known limits (stated, not fixed):

* Non-canonical base64url and high-S ES256 signature twins verify. No later stage may key on the
  raw token string (replay, dedupe, audit IDs).
* With a healthy JWKS, a key removed at the IdP stays trusted until the TTL (1 hour by default),
  alongside access tokens that last 15 minutes.
* Real Cognito tokens are checked only by D12-10 (see docs/findings/sso.md).

Network access is injected (``fetch``); this module opens no sockets itself.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import logging
import math
import re
import time
import types
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from sto.domain.errors import PermanentError, TransientError

_log = logging.getLogger(__name__)

SUPPORTED_ALGORITHMS = ("RS256", "ES256")
MAX_TOKEN_BYTES = 16 * 1024
_MIN_RSA_BITS = 2048
_MAX_RSA_BITS = 8192
_MIN_RSA_EXPONENT = 65537
MAX_LEEWAY_SECONDS = 300


class InvalidTokenError(PermanentError):
    """The token is refused. ``reason`` is a stable code; messages never carry the token."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class OidcConfig:
    """What to trust. ``audience_claim``, ``token_use``, ``groups_claim`` absorb vendor quirks."""

    issuer: str
    audience: str
    jwks_uri: str | None = None
    algorithms: tuple[str, ...] = ("RS256",)
    leeway_seconds: int = 60
    audience_claim: str = "aud"
    token_use: str | None = None
    groups_claim: str = "groups"

    def __post_init__(self) -> None:
        if (
            not self.issuer.startswith("https://")
            or len(self.issuer) <= len("https://")
            or any(c.isspace() for c in self.issuer)
        ):
            raise ValueError("issuer must be an https URL with a host")
        if not self.audience:
            raise ValueError("audience must be non-empty")
        if self.jwks_uri is not None and not self.jwks_uri.startswith("https://"):
            raise ValueError("jwks_uri must be https")
        if not self.algorithms or any(a not in SUPPORTED_ALGORITHMS for a in self.algorithms):
            raise ValueError(f"algorithm must be among {SUPPORTED_ALGORITHMS}")
        if not 0 <= self.leeway_seconds <= MAX_LEEWAY_SECONDS:
            raise ValueError(f"leeway_seconds must be between 0 and {MAX_LEEWAY_SECONDS}")


_REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]", re.ASCII)
_POOL = re.compile(r"([a-z]{2}(?:-[a-z]+)+-[0-9])_[A-Za-z0-9]+", re.ASCII)


def cognito_config(*, region: str, user_pool_id: str, client_id: str) -> OidcConfig:
    """The whole Cognito-specific part: an issuer URL and three claim names. Config only."""
    if not _REGION.fullmatch(region):
        raise ValueError("region is not a valid AWS region name")
    pool = _POOL.fullmatch(user_pool_id)
    if not pool:
        raise ValueError("user_pool_id is not a valid user pool ID")
    if pool.group(1) != region:
        raise ValueError("user_pool_id region prefix does not match region")
    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    return OidcConfig(
        issuer=issuer,
        audience=client_id,
        jwks_uri=f"{issuer}/.well-known/jwks.json",
        audience_claim="client_id",  # access tokens carry client_id, not aud
        token_use="access",
        groups_claim="cognito:groups",
    )


@dataclass(frozen=True)
class VerifiedToken:
    """A validated token. ``claims`` is deeply read-only and left out of equality and hash."""

    subject: str
    issuer: str
    groups: tuple[str, ...]
    auth_time: float | None
    expires_at: float
    claims: Mapping[str, Any] = field(repr=False, compare=False)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return types.MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


# --- keys ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Jwk:
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    alg: str | None = None


def _b64d(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not base64url") from exc


def _int(value: str) -> int:
    return int.from_bytes(_b64d(value), "big")


def _load_key(jwk: Mapping[str, Any]) -> Jwk | None:
    """A public key from a JWK, or ``None`` for an entry we do not support or must not use."""
    if "d" in jwk or jwk.get("use") not in (None, "sig"):
        return None
    ops = jwk.get("key_ops")
    if ops is not None and (not isinstance(ops, list) or "verify" not in ops):
        return None
    alg = jwk.get("alg")
    if alg is not None and not isinstance(alg, str):
        return None
    try:
        if jwk.get("kty") == "RSA":
            n, e = _int(jwk["n"]), _int(jwk["e"])
            if n % 2 == 0 or not _MIN_RSA_BITS <= n.bit_length() <= _MAX_RSA_BITS:
                return None
            if e < _MIN_RSA_EXPONENT:
                return None
            return Jwk(rsa.RSAPublicNumbers(e, n).public_key(), alg)
        if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            point = ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1())
            return Jwk(point.public_key(), alg)
    except (KeyError, ValueError, TypeError):
        return None
    return None


def _parse(doc: object) -> tuple[dict[str, Jwk], int]:
    """``(kid -> key, number of entries listed)``. ``ValueError`` if the document is malformed."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("keys"), list):
        raise ValueError("JWKS must be an object with a keys list")
    seen: set[str] = set()
    duplicated: set[str] = set()
    keys: dict[str, Jwk] = {}
    for entry in doc["keys"]:
        if not isinstance(entry, Mapping):
            raise ValueError("JWKS key entries must be objects")
        kid = entry.get("kid")
        if not isinstance(kid, str):
            continue
        if kid in seen:
            duplicated.add(kid)
        seen.add(kid)
        key = _load_key(entry)
        if key is not None:
            keys[kid] = key
    if duplicated:
        _log.warning("JWKS contains %d duplicated kid value(s); ignoring them", len(duplicated))
    for kid in duplicated:
        keys.pop(kid, None)
    return keys, len(doc["keys"])


def parse_jwks(doc: object) -> dict[str, Jwk]:
    return _parse(doc)[0]


class JwksSource(Protocol):
    def get(self, kid: str) -> Jwk | None:
        """The key for ``kid``, ``None`` if the issuer has no such key. Transient on failure."""
        ...


class StaticJwks:
    """A fixed key set, for tests and local use."""

    def __init__(self, doc: Mapping[str, Any]) -> None:
        self._keys = parse_jwks(doc)

    def get(self, kid: str) -> Jwk | None:
        return self._keys.get(kid)


class CachedJwks:
    """Fetches a JWKS through ``fetch(uri) -> bytes`` and caches it. See the module docstring.

    A refresh is attempted when the cache is older than ``ttl_seconds`` or a ``kid`` is unknown,
    at most once per ``min_refetch_seconds`` (cold start included). Cached keys keep working
    through a failed refresh until ``max_stale_seconds`` after the last successful fetch.
    ``clock`` must be monotonic.
    """

    def __init__(
        self,
        uri: str,
        fetch: Callable[[str], bytes],
        *,
        ttl_seconds: float = 3600,
        min_refetch_seconds: float = 30,
        max_stale_seconds: float = 6 * 3600,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not uri.startswith("https://"):
            raise ValueError("JWKS URI must be https")
        if ttl_seconds <= 0 or min_refetch_seconds <= 0:
            raise ValueError("ttl_seconds and min_refetch_seconds must be positive")
        if max_stale_seconds < ttl_seconds:
            raise ValueError("max_stale_seconds must be at least ttl_seconds")
        self._uri, self._fetch, self._clock = uri, fetch, clock
        self._ttl, self._min, self._max_stale = ttl_seconds, min_refetch_seconds, max_stale_seconds
        self._keys: dict[str, Jwk] | None = None
        self._fetched_at = 0.0
        self._attempted_at = float("-inf")
        self._last_failed = False
        self._seq = 0  # attempts started
        self._outcome_seq = 0  # newest attempt whose outcome is recorded

    def _refresh(self) -> None:
        self._seq += 1
        mine = self._seq
        started = self._attempted_at = self._clock()
        try:
            keys, listed = _parse(json.loads(self._fetch(self._uri)))
            if listed and not keys:
                raise ValueError("JWKS listed keys but none are usable")
        except Exception as exc:  # network, JSON or shape: all mean "keys unavailable"
            if mine > self._outcome_seq:
                self._outcome_seq, self._last_failed = mine, True
            raise TransientError(f"JWKS unavailable: {type(exc).__name__}") from exc
        if mine > self._outcome_seq:  # a slow older fetch must not undo a newer one
            self._outcome_seq, self._last_failed = mine, False
            self._keys, self._fetched_at = keys, started

    def get(self, kid: str) -> Jwk | None:
        now = self._clock()
        can_try = now - self._attempted_at >= self._min
        if self._keys is None:
            if not can_try:
                raise TransientError("JWKS unavailable: retry window")
            self._refresh()
        elif (now - self._fetched_at >= self._ttl or kid not in self._keys) and can_try:
            with contextlib.suppress(TransientError):  # keep serving the cached set
                self._refresh()
        keys = self._keys
        if keys is None or self._clock() - self._fetched_at >= self._max_stale:
            raise TransientError("JWKS unavailable: no fresh keys")
        key = keys.get(kid)
        if key is None and self._last_failed:
            raise TransientError("JWKS unavailable: cannot rule out a rotated key")
        return key


# --- validation ----------------------------------------------------------------------------


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise ValueError("duplicate key")
    return out


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def _decode_segment(segment: str) -> dict[str, Any]:
    try:
        text = _b64d(segment).decode("utf-8")  # RFC 7519: UTF-8 only; a BOM fails in json
        value = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:
        raise InvalidTokenError("malformed", "segment is not UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise InvalidTokenError("malformed", "segment is not a JSON object")
    return value


def _number(claims: Mapping[str, Any], name: str) -> float | None:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InvalidTokenError("malformed", f"{name} is not a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise InvalidTokenError("malformed", f"{name} is out of range") from exc
    if not math.isfinite(number):
        raise InvalidTokenError("malformed", f"{name} is not finite")
    return number


class OidcValidator:
    def __init__(
        self, config: OidcConfig, jwks: JwksSource, *, clock: Callable[[], float] = time.time
    ) -> None:
        self._cfg, self._jwks, self._clock = config, jwks, clock

    def validate(self, token: str) -> VerifiedToken:
        cfg = self._cfg
        if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES:
            raise InvalidTokenError("malformed", "missing or oversized token")
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidTokenError("malformed", "expected three segments")
        header = _decode_segment(parts[0])
        claims = _decode_segment(parts[1])

        alg = header.get("alg")
        if alg not in cfg.algorithms:
            raise InvalidTokenError("bad_algorithm", "algorithm is not allowed")
        if "crit" in header:
            raise InvalidTokenError("malformed", "critical headers are not supported")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidTokenError("unknown_key", "no kid")
        jwk = self._jwks.get(kid)
        if jwk is None:
            raise InvalidTokenError("unknown_key", "no such key")
        if jwk.alg is not None and jwk.alg != alg:
            raise InvalidTokenError("bad_algorithm", "key is bound to another algorithm")
        try:
            signature = _b64d(parts[2])
        except ValueError as exc:
            raise InvalidTokenError("bad_signature", "signature is not base64url") from exc
        self._check_signature(jwk.key, alg, f"{parts[0]}.{parts[1]}".encode("ascii"), signature)

        return self._check_claims(claims)

    @staticmethod
    def _check_signature(
        key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
        alg: str,
        message: bytes,
        signature: bytes,
    ) -> None:
        try:
            if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
                key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
                return
            if alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey):
                if len(signature) != 64:
                    raise InvalidSignature
                r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
                key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
                return
        except InvalidSignature:
            pass
        raise InvalidTokenError("bad_signature", "signature does not verify")

    def _audiences(self, claims: Mapping[str, Any]) -> list[Any]:
        aud = claims.get(self._cfg.audience_claim)
        if isinstance(aud, str):
            return [aud]
        if self._cfg.audience_claim == "aud" and isinstance(aud, list):
            if not all(isinstance(a, str) for a in aud):
                raise InvalidTokenError("bad_audience", "audience entries must be strings")
            return aud
        return []

    def _check_claims(self, claims: dict[str, Any]) -> VerifiedToken:
        cfg, now = self._cfg, self._clock()
        if claims.get("iss") != cfg.issuer:
            raise InvalidTokenError("bad_issuer", "issuer is not trusted")
        if cfg.audience not in self._audiences(claims):
            raise InvalidTokenError("bad_audience", "audience does not include this API")
        exp = _number(claims, "exp")
        if exp is None:
            raise InvalidTokenError("missing_claim", "exp")
        if now >= exp + cfg.leeway_seconds:
            raise InvalidTokenError("expired", "token has expired")
        nbf = _number(claims, "nbf")
        if nbf is not None and now < nbf - cfg.leeway_seconds:
            raise InvalidTokenError("not_yet_valid", "token is not valid yet")
        _number(claims, "iat")  # present means finite; no future check
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise InvalidTokenError("missing_claim", "sub")
        if cfg.token_use is not None and claims.get("token_use") != cfg.token_use:
            raise InvalidTokenError("bad_token_use", "wrong kind of token")
        auth_time = _number(claims, "auth_time")
        if auth_time is not None and auth_time > now + cfg.leeway_seconds:
            raise InvalidTokenError("bad_auth_time", "auth_time is in the future")
        return VerifiedToken(
            subject=sub,
            issuer=cfg.issuer,
            groups=self._groups(claims.get(cfg.groups_claim)),
            auth_time=auth_time,
            expires_at=exp,
            claims=_freeze(claims),
        )

    @staticmethod
    def _groups(value: object) -> tuple[str, ...]:
        """A string or list of strings; blanks are dropped (the trigger writes a blank)."""
        if value is None:
            return ()
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list) and all(isinstance(g, str) for g in value):
            return tuple(g for g in value if g.strip())
        raise InvalidTokenError("malformed", "groups claim must be a string or list of strings")
