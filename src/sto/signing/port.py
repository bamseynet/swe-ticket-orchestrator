"""The signer port: one interface for audit checkpoints, step tokens and GitHub App JWTs.

Two protocols, so verifying never needs signing power:

* ``Verifier``: ``verify`` plus ``public_keys`` (JWKS-shaped). Brokers and the JWKS endpoint
  hold only this.
* ``Signer``: a ``Verifier`` that can also ``sign``. Only the dispatcher holds one.

Every ``Signature`` names the ``key_id`` and JOSE ``algorithm`` (``HS256``, ``RS256``) that made
it, so keys rotate and a JWT header can be built before signing.

Failure rules (PLAN 6.2): ``verify`` returns ``False`` only for a signature that is wrong, i.e.
forged, tampered, or made by an unknown key or algorithm. It never returns ``False`` because
something broke. A remote failure (KMS throttle, timeout) raises ``TransientError`` from ``sign``
and from ``verify``. Bad configuration or malformed input raises ``SigningError`` (permanent).

Nothing in a signature separates domains, so use one key per purpose: audit checkpoints, step
tokens and GitHub JWTs each get their own ``Signer`` and key ID.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, Self, runtime_checkable

from sto.domain.errors import PermanentError

_B64URL = re.compile(r"[A-Za-z0-9_-]+")


class SigningError(PermanentError):
    """Bad key configuration or a malformed signature. Messages never contain key material."""


@dataclass(frozen=True)
class Signature:
    """A signature plus the ID of the key and the JOSE algorithm that produced it.

    ``value`` is the raw signature bytes. Only ``HS256`` and ``RS256`` are defined for now; an
    algorithm with a different raw layout (ES256 as JOSE ``r||s``) needs its own issue.
    """

    key_id: str
    algorithm: str
    value: bytes

    def __post_init__(self) -> None:
        # Printable only: key IDs reach logs, so control characters would allow log injection.
        if not isinstance(self.key_id, str) or not self.key_id or not self.key_id.isprintable():
            raise SigningError("signature key_id must be a non-empty printable string")
        if (
            not isinstance(self.algorithm, str)
            or not self.algorithm
            or "." in self.algorithm
            or not self.algorithm.isprintable()
        ):
            raise SigningError("signature algorithm must be printable, non-empty and have no dots")
        if not isinstance(self.value, bytes) or not self.value:
            raise SigningError("signature value must be non-empty bytes")

    def encode(self) -> str:
        """Canonical text: ``key_id.algorithm.base64url(value)`` with no padding."""

        b64 = base64.urlsafe_b64encode(self.value).decode("ascii").rstrip("=")
        return f"{self.key_id}.{self.algorithm}.{b64}"

    @classmethod
    def decode(cls, text: str) -> Self:
        """Strict inverse of ``encode``: anything that is not canonical text is refused."""
        if not isinstance(text, str):
            raise SigningError("malformed signature")
        parts = text.rsplit(".", 2)  # the key ID may contain dots; algorithm and base64url never do
        if len(parts) != 3 or not _B64URL.fullmatch(parts[2]):
            raise SigningError("malformed signature")
        key_id, algorithm, b64 = parts
        try:
            value = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            sig = cls(key_id=key_id, algorithm=algorithm, value=value)
        except ValueError as exc:  # binascii.Error is a ValueError
            raise SigningError("malformed signature") from exc
        if sig.encode() != text:  # rejects altered trailing bits and any other non-canonical form
            raise SigningError("malformed signature")
        return sig


@runtime_checkable
class Verifier(Protocol):
    """Verify signatures and publish public keys. Holds no signing power."""

    def verify(self, message: bytes, signature: Signature) -> bool:
        """True only if ``signature`` is valid for ``message`` under a key this verifier knows."""
        ...

    def public_keys(self) -> Sequence[Mapping[str, str]]:
        """JWKS-shaped public keys (the ``keys`` array), each with ``kid``, ``kty`` and ``alg``.

        Symmetric implementations have no public key and return an empty sequence: their keys are
        local only and can never be published.
        """
        ...


@runtime_checkable
class Signer(Verifier, Protocol):
    """A ``Verifier`` that can sign. KMS-backed implementations satisfy the same protocol."""

    @property
    def key_id(self) -> str:
        """ID of the key that ``sign`` currently uses."""
        ...

    @property
    def algorithm(self) -> str:
        """JOSE name of the algorithm ``sign`` uses (``HS256``, ``RS256``), known before signing."""
        ...

    def sign(self, message: bytes) -> Signature: ...
