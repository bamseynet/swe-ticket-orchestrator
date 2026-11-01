"""A fake OIDC issuer for tests and local use. Keys are generated in memory, never real.

It signs real RS256 or ES256 JWTs and serves a JWKS, so the validator is exercised end to end.
``issue`` builds a normal token; ``extra``, ``drop`` and ``header`` bend it to make bad ones.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _uint(value: int, length: int | None = None) -> str:
    size = length or max(1, (value.bit_length() + 7) // 8)
    return _b64(value.to_bytes(size, "big"))


class FakeIssuer:
    def __init__(
        self,
        *,
        issuer: str,
        key_id: str = "fake-1",
        algorithm: str = "RS256",
        groups_claim: str = "groups",
        clock: Callable[[], float] = time.time,
    ) -> None:
        if algorithm not in ("RS256", "ES256"):
            raise ValueError("algorithm must be RS256 or ES256")
        self.issuer, self.algorithm, self.groups_claim = issuer, algorithm, groups_claim
        self._clock = clock
        self._keys: dict[str, PrivateKey] = {}
        self._current = key_id
        self._keys[key_id] = self._new_key()

    def _new_key(self) -> PrivateKey:
        if self.algorithm == "RS256":
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return ec.generate_private_key(ec.SECP256R1())

    def rotate(self, new_key_id: str, *, keep_old: bool = True) -> None:
        """Start signing with a new key. With ``keep_old=False`` the old key leaves the JWKS."""
        if new_key_id in self._keys:
            raise ValueError("key id already used")
        old = self._current
        self._keys[new_key_id] = self._new_key()
        self._current = new_key_id
        if not keep_old:
            del self._keys[old]

    def jwks(self) -> dict[str, Any]:
        keys: list[dict[str, str]] = []
        for kid, key in self._keys.items():
            pub = key.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                nums = pub.public_numbers()
                keys.append(
                    {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
                     "n": _uint(nums.n), "e": _uint(nums.e)}
                )  # fmt: skip
            else:
                point = pub.public_numbers()
                keys.append(
                    {"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
                     "x": _uint(point.x, 32), "y": _uint(point.y, 32)}
                )  # fmt: skip
        return {"keys": keys}

    def fetch(self, uri: str) -> bytes:
        """A ``fetch`` for :class:`~sto.identity.oidc.CachedJwks`: serves the JWKS, no network."""
        return json.dumps(self.jwks()).encode()

    def issue(
        self,
        *,
        sub: str,
        audience: str | Sequence[str],
        groups: Iterable[str] | None = None,
        expires_in: float = 900,
        auth_time: float | None = None,
        issuer_claim: str | None = None,
        extra: Mapping[str, Any] | None = None,
        drop: Iterable[str] = (),
        header: Mapping[str, Any] | None = None,
    ) -> str:
        now = self._clock()
        claims: dict[str, Any] = {
            "iss": issuer_claim if issuer_claim is not None else self.issuer,
            "sub": sub,
            "aud": audience if isinstance(audience, str) else list(audience),
            "iat": now,
            "exp": now + expires_in,
        }
        if groups is not None:
            claims[self.groups_claim] = list(groups)
        if auth_time is not None:
            claims["auth_time"] = auth_time
        claims.update(extra or {})
        for name in drop:
            claims.pop(name, None)
        return self.issue_raw(payload=json.dumps(claims).encode(), header=header)

    def issue_raw(self, *, payload: bytes, header: Mapping[str, Any] | None = None) -> str:
        """Sign arbitrary payload bytes. A header value of ``None`` removes that header field."""
        head: dict[str, Any] = {"alg": self.algorithm, "typ": "JWT", "kid": self._current}
        head.update(header or {})
        head = {k: v for k, v in head.items() if v is not None}
        signing_input = f"{_b64(json.dumps(head).encode())}.{_b64(payload)}"
        return f"{signing_input}.{_b64(self._sign(signing_input.encode('ascii')))}"

    def _sign(self, message: bytes) -> bytes:
        key = self._keys[self._current]
        if isinstance(key, rsa.RSAPrivateKey):
            return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
