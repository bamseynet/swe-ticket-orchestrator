"""OIDC token validation by issuer plus JWKS (PLAN 9.2, ADR-0008).

The API trusts *an issuer and its keys*, not a particular vendor. Everything that differs for
Cognito is a value in :class:`OidcConfig`, built by :func:`cognito_config`; the validator has no
vendor branches, so another broker can replace Cognito by changing config.

Refusals (:class:`InvalidTokenError`, permanent, with a stable ``reason``): malformed token,
algorithm outside the allow-list (so ``none`` and HMAC-with-public-key confusion are out), unknown
``kid``, bad signature, wrong issuer, wrong audience, expired or not-yet-valid, missing ``sub``
or ``exp``, and a wrong ``token_use`` when one is required. A JWKS that cannot be fetched is
:class:`~sto.domain.errors.TransientError`, never "invalid token".

Network access is injected (``fetch``); this module opens no sockets itself.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from sto.domain.errors import PermanentError, TransientError

SUPPORTED_ALGORITHMS = ("RS256", "ES256")
MAX_TOKEN_BYTES = 16 * 1024
_MIN_RSA_BITS = 2048

D12_TEST_PLAN = """\
D12-10 test plan: what only a real IdP can prove (L11, FF-13)

The fake issuer proves our validation logic. It cannot prove how Cognito and a real enterprise
IdP behave, so these are run once against real ones in D12-10 and the results go in the SSO
findings and ADR-0008:

Group list size
- Put a test user in far more groups than the app needs; confirm sign-in either succeeds with
  only the app-relevant IDs or fails visibly. Record the real limit (the 2,048 character
  attribute cap is documented, not yet observed).
- Confirm the Inbound federation trigger sends immutable group IDs only, never display names.

Step-up
- Sign in with prompt=login and max_age through managed login; confirm the IdP is re-prompted
  and that auth_time in the token moves, and does not move on a plain refresh.
- Reuse a session cookie; confirm the token is fresh but auth_time (our as_of) is not.

Revocation
- Remove a user from their last group at the IdP; sign in again; confirm the groups attribute is
  really cleared (Cognito keeps old attributes unless the trigger writes an explicit blank).
- Disable the user in the pool; confirm the API refuses within one request, and record how long
  an already-issued access token (15 minute default) stays valid at the JWKS check alone.

Also check against the real pool
- Access tokens carry client_id and token_use=access and no aud; ID tokens carry aud. Confirm
  cognito_config's claim names and the groups claim name match what the pool really issues.
- A federated user cannot overwrite the mapped groups attribute (self-write attempt fails).
- Key rotation: rotate the pool's signing key and confirm CachedJwks picks up the new kid.

Evidence goes in docs/findings/sso.md; anything unproven keeps its fallback in ADR-0008.
"""


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
        if not self.issuer or not self.issuer.startswith("https://"):
            raise ValueError("issuer must be a non-empty https URL")
        if not self.audience:
            raise ValueError("audience must be non-empty")
        if self.jwks_uri is not None and not self.jwks_uri.startswith("https://"):
            raise ValueError("jwks_uri must be https")
        if not self.algorithms or any(a not in SUPPORTED_ALGORITHMS for a in self.algorithms):
            raise ValueError(f"algorithm must be among {SUPPORTED_ALGORITHMS}")
        if self.leeway_seconds < 0:
            raise ValueError("leeway_seconds must be >= 0")


_REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")
_POOL = re.compile(r"[a-z0-9-]+_[A-Za-z0-9]+")


def cognito_config(*, region: str, user_pool_id: str, client_id: str) -> OidcConfig:
    """The whole Cognito-specific part: an issuer URL and three claim names. Config only."""
    if not _REGION.fullmatch(region):
        raise ValueError("region is not a valid AWS region name")
    if not _POOL.fullmatch(user_pool_id):
        raise ValueError("user_pool_id is not a valid user pool ID")
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
    subject: str
    issuer: str
    groups: tuple[str, ...]
    auth_time: float | None
    expires_at: float
    claims: Mapping[str, Any] = field(repr=False)


# --- keys ----------------------------------------------------------------------------------

PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


def _b64d(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not base64url") from exc


def _int(value: str) -> int:
    return int.from_bytes(_b64d(value), "big")


def _load_key(jwk: Mapping[str, Any]) -> PublicKey | None:
    """A public key from a JWK, or ``None`` for an entry we do not support or that is unusable."""
    try:
        if jwk.get("kty") == "RSA":
            rsa_key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
            return rsa_key if rsa_key.key_size >= _MIN_RSA_BITS else None
        if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            point = ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1())
            return point.public_key()
    except (KeyError, ValueError, TypeError):
        return None
    return None


def parse_jwks(doc: object) -> dict[str, PublicKey]:
    """``kid -> key``. Raises ``ValueError`` if the document itself is malformed."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("keys"), list):
        raise ValueError("JWKS must be an object with a keys list")
    keys: dict[str, PublicKey] = {}
    for entry in doc["keys"]:
        if not isinstance(entry, Mapping):
            raise ValueError("JWKS key entries must be objects")
        kid = entry.get("kid")
        if not isinstance(kid, str) or entry.get("use") not in (None, "sig"):
            continue
        key = _load_key(entry)
        if key is not None:
            keys[kid] = key
    return keys


class JwksSource(Protocol):
    def get(self, kid: str) -> PublicKey | None:
        """The key for ``kid``, ``None`` if the issuer has no such key. Transient on failure."""
        ...


class StaticJwks:
    """A fixed key set, for tests and local use."""

    def __init__(self, doc: Mapping[str, Any]) -> None:
        self._keys = parse_jwks(doc)

    def get(self, kid: str) -> PublicKey | None:
        return self._keys.get(kid)


class CachedJwks:
    """Fetches a JWKS through ``fetch(uri) -> bytes`` and caches it.

    A refresh happens when the cache is older than ``ttl_seconds``, or when a ``kid`` is unknown
    and the last attempt was at least ``min_refetch_seconds`` ago, so key rotation is picked up
    but a stream of junk ``kid`` values cannot make us fetch on every request. If a TTL refresh
    fails, the stale keys keep working; with nothing cached the failure is transient.
    """

    def __init__(
        self,
        uri: str,
        fetch: Callable[[str], bytes],
        *,
        ttl_seconds: float = 3600,
        min_refetch_seconds: float = 30,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not uri.startswith("https://"):
            raise ValueError("JWKS URI must be https")
        self._uri, self._fetch, self._clock = uri, fetch, clock
        self._ttl, self._min = ttl_seconds, min_refetch_seconds
        self._keys: dict[str, PublicKey] | None = None
        self._fetched_at = 0.0
        self._attempted_at = float("-inf")

    def _refresh(self) -> None:
        self._attempted_at = self._clock()
        try:
            keys = parse_jwks(json.loads(self._fetch(self._uri)))
        except Exception as exc:  # network, JSON or shape: all mean "keys unavailable"
            raise TransientError(f"JWKS unavailable: {type(exc).__name__}") from exc
        self._keys, self._fetched_at = keys, self._attempted_at

    def get(self, kid: str) -> PublicKey | None:
        now = self._clock()
        if self._keys is None:
            self._refresh()
        elif now - self._fetched_at >= self._ttl and now - self._attempted_at >= self._min:
            with contextlib.suppress(TransientError):  # keep serving the stale set
                self._refresh()
        elif kid not in self._keys and now - self._attempted_at >= self._min:
            self._refresh()
        assert self._keys is not None
        return self._keys.get(kid)


# --- validation ----------------------------------------------------------------------------


def _decode_segment(segment: str) -> dict[str, Any]:
    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out = dict(pairs)
        if len(out) != len(pairs):
            raise ValueError("duplicate key")
        return out

    try:
        value = json.loads(_b64d(segment), object_pairs_hook=no_dupes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidTokenError("malformed", "segment is not base64url JSON") from exc
    if not isinstance(value, dict):
        raise InvalidTokenError("malformed", "segment is not a JSON object")
    return value


def _number(claims: Mapping[str, Any], name: str) -> float | None:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InvalidTokenError("malformed", f"{name} is not a number")
    return float(value)


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
        key = self._jwks.get(kid)
        if key is None:
            raise InvalidTokenError("unknown_key", "no such key")
        try:
            signature = _b64d(parts[2])
        except ValueError as exc:
            raise InvalidTokenError("bad_signature", "signature is not base64url") from exc
        self._check_signature(key, alg, f"{parts[0]}.{parts[1]}".encode("ascii"), signature)

        return self._check_claims(claims)

    @staticmethod
    def _check_signature(key: PublicKey, alg: str, message: bytes, signature: bytes) -> None:
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

    def _check_claims(self, claims: dict[str, Any]) -> VerifiedToken:
        cfg, now = self._cfg, self._clock()
        if claims.get("iss") != cfg.issuer:
            raise InvalidTokenError("bad_issuer", "issuer is not trusted")
        aud = claims.get(cfg.audience_claim)
        audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if cfg.audience not in audiences:
            raise InvalidTokenError("bad_audience", "audience does not include this API")
        exp = _number(claims, "exp")
        if exp is None:
            raise InvalidTokenError("missing_claim", "exp")
        if now > exp + cfg.leeway_seconds:
            raise InvalidTokenError("expired", "token has expired")
        nbf = _number(claims, "nbf")
        if nbf is not None and now < nbf - cfg.leeway_seconds:
            raise InvalidTokenError("not_yet_valid", "token is not valid yet")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise InvalidTokenError("missing_claim", "sub")
        if cfg.token_use is not None and claims.get("token_use") != cfg.token_use:
            raise InvalidTokenError("bad_token_use", "wrong kind of token")
        return VerifiedToken(
            subject=sub,
            issuer=cfg.issuer,
            groups=self._groups(claims.get(cfg.groups_claim)),
            auth_time=_number(claims, "auth_time"),
            expires_at=exp,
            claims=claims,
        )

    @staticmethod
    def _groups(value: object) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list) and all(isinstance(g, str) for g in value):
            return tuple(value)
        raise InvalidTokenError("malformed", "groups claim must be a string or list of strings")
