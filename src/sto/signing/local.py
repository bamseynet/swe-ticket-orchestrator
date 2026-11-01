"""Local signer: HMAC-SHA256 (JOSE ``HS256``) from the standard library. For tests and single host.

The key is symmetric, so there is no public key to publish and it must never leave this process.
Error messages never include key IDs or secrets (a swapped argument would put a secret in a key
ID). The object refuses pickling and copying, shows only key IDs in ``repr``, and keeps keys in a
slot rather than ``vars()``. That limits accidents; it does not defend against code in the
same process.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping, Sequence
from typing import NoReturn

from .port import Signature, SigningError

ALGORITHM = "HS256"
MIN_SECRET_BYTES = 32


def _check(key_id: object, secret: object) -> None:
    if not isinstance(key_id, str) or not key_id or not key_id.isprintable():
        raise SigningError("key_id must be a non-empty printable string")
    if not isinstance(secret, bytes):
        raise SigningError("secret must be bytes")
    if len(secret) < MIN_SECRET_BYTES:
        raise SigningError(f"secret must be at least {MIN_SECRET_BYTES} bytes")


class LocalSigner:
    """Signs with one current key. ``retired`` keys still verify, so rotation is safe."""

    __slots__ = ("_key_id", "_keys")

    def __init__(
        self, *, key_id: str, secret: bytes, retired: Mapping[str, bytes] | None = None
    ) -> None:
        _check(key_id, secret)
        try:
            keys = dict(retired or {})
        except (TypeError, ValueError) as exc:
            raise SigningError("retired must be a mapping of key ID to secret") from exc
        if key_id in keys:
            raise SigningError("retired keys must not include the current key")
        for rid, rsecret in keys.items():
            _check(rid, rsecret)
        keys[key_id] = secret
        self._key_id = key_id
        self._keys = keys

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return ALGORITHM

    def sign(self, message: bytes) -> Signature:
        if not isinstance(message, bytes):
            raise SigningError("message must be bytes")
        mac = hmac.new(self._keys[self._key_id], message, hashlib.sha256).digest()
        return Signature(key_id=self._key_id, algorithm=ALGORITHM, value=mac)

    def verify(self, message: bytes, signature: Signature) -> bool:
        if not isinstance(message, bytes) or not isinstance(signature, Signature):
            raise SigningError("verify needs bytes and a Signature")
        secret = self._keys.get(signature.key_id)
        if secret is None or signature.algorithm != ALGORITHM:
            return False
        expected = hmac.new(secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature.value)

    def public_keys(self) -> Sequence[Mapping[str, str]]:
        return ()  # symmetric: nothing publishable

    def __repr__(self) -> str:
        retired = sorted(k for k in self._keys if k != self._key_id)
        return f"LocalSigner(key_id={self._key_id!r}, retired={retired!r})"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise SigningError("LocalSigner holds key material and cannot be pickled")

    def __copy__(self) -> NoReturn:
        raise SigningError("LocalSigner holds key material and cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise SigningError("LocalSigner holds key material and cannot be copied")
