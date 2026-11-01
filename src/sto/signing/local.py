"""Local signer: HMAC-SHA256 from the standard library. For tests and single-host use.

Key material is never exposed: ``repr`` shows only key IDs, and nothing here logs.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping

from .port import Signature, SigningError

ALGORITHM = "HMAC-SHA256"
MIN_SECRET_BYTES = 32


def _check(key_id: str, secret: bytes) -> None:
    if not key_id:
        raise SigningError("key_id must not be empty")
    if len(secret) < MIN_SECRET_BYTES:
        raise SigningError(f"secret for key {key_id!r} must be at least {MIN_SECRET_BYTES} bytes")


class LocalSigner:
    """Signs with one current key. ``retired`` keys still verify, so rotation is safe."""

    def __init__(
        self, *, key_id: str, secret: bytes, retired: Mapping[str, bytes] | None = None
    ) -> None:
        _check(key_id, secret)
        keys = dict(retired or {})
        for rid, rsecret in keys.items():
            _check(rid, rsecret)
        keys[key_id] = secret
        self._key_id = key_id
        self._keys = keys

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, message: bytes) -> Signature:
        mac = hmac.new(self._keys[self._key_id], message, hashlib.sha256).digest()
        return Signature(key_id=self._key_id, algorithm=ALGORITHM, value=mac)

    def verify(self, message: bytes, signature: Signature) -> bool:
        secret = self._keys.get(signature.key_id)
        if secret is None or signature.algorithm != ALGORITHM:
            return False
        expected = hmac.new(secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature.value)

    def __repr__(self) -> str:
        retired = sorted(k for k in self._keys if k != self._key_id)
        return f"LocalSigner(key_id={self._key_id!r}, retired={retired!r})"

    __str__ = __repr__
