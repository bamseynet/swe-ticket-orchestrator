"""The signer port. One interface for audit checkpoints, step tokens and GitHub App JWTs.

Implementations hold the key material; callers only ever see a ``key_id`` and signatures. Every
signature names the key that made it, so keys can rotate: verify looks the key up by that ID.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Protocol, Self, runtime_checkable


class SigningError(Exception):
    """Bad key configuration or a malformed signature. Messages never contain key material."""


@dataclass(frozen=True)
class Signature:
    """A signature plus the ID of the key and the algorithm that produced it."""

    key_id: str
    algorithm: str
    value: bytes

    def encode(self) -> str:
        """Compact text form ``key_id.algorithm.base64url(value)`` for tokens and audit records."""
        b64 = base64.urlsafe_b64encode(self.value).decode("ascii")
        return f"{self.key_id}.{self.algorithm}.{b64}"

    @classmethod
    def decode(cls, text: str) -> Self:
        # The key ID may contain dots; the algorithm and base64url never do.
        try:
            key_id, algorithm, b64 = text.rsplit(".", 2)
            value = base64.urlsafe_b64decode(b64.encode("ascii"))
        except (ValueError, binascii.Error) as exc:
            raise SigningError("malformed signature") from exc
        if not key_id or not algorithm:
            raise SigningError("malformed signature")
        return cls(key_id=key_id, algorithm=algorithm, value=value)


@runtime_checkable
class Signer(Protocol):
    """Sign and verify byte strings. KMS-backed implementations satisfy the same protocol."""

    @property
    def key_id(self) -> str:
        """ID of the key that ``sign`` currently uses."""
        ...

    def sign(self, message: bytes) -> Signature: ...

    def verify(self, message: bytes, signature: Signature) -> bool:
        """True only if ``signature`` is valid for ``message`` under a key this signer knows."""
        ...
