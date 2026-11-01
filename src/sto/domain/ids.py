"""ULID-based identifiers. Each kind of ID is its own type, so a ``GateId`` is never a ``RunId``."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Self

from .errors import InvalidIdError

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32
_DECODE = {c: i for i, c in enumerate(_ALPHABET)}
_MAX = (1 << 128) - 1


@dataclass(frozen=True, order=True)
class Ulid:
    """128 bits: 48-bit millisecond timestamp, 80 bits of randomness. Sorts by creation time."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= _MAX:
            raise InvalidIdError(f"ULID out of range: {self.value}")

    @classmethod
    def from_parts(cls, timestamp_ms: int, entropy: bytes) -> Self:
        """Pure constructor: the caller supplies the clock and the randomness."""
        if not 0 <= timestamp_ms < 1 << 48:
            raise InvalidIdError("ULID timestamp must fit in 48 bits")
        if len(entropy) != 10:
            raise InvalidIdError("ULID entropy must be exactly 10 bytes")
        return cls((timestamp_ms << 80) | int.from_bytes(entropy, "big"))

    @classmethod
    def new(cls) -> Self:
        """Impure edge: reads the system clock and OS randomness. Never call from the reducer."""
        return cls.from_parts(time.time_ns() // 1_000_000, os.urandom(10))

    @classmethod
    def parse(cls, text: str) -> Self:
        if len(text) != 26:
            raise InvalidIdError(f"ULID must be 26 characters, got {len(text)}")
        value = 0
        for ch in text.upper():
            digit = _DECODE.get(ch)
            if digit is None:
                raise InvalidIdError(f"invalid ULID character {ch!r}")
            value = (value << 5) | digit
        if value > _MAX:
            raise InvalidIdError("ULID overflows 128 bits")
        return cls(value)

    @property
    def timestamp_ms(self) -> int:
        return self.value >> 80

    def __str__(self) -> str:
        v, out = self.value, []
        for _ in range(26):
            out.append(_ALPHABET[v & 31])
            v >>= 5
        return "".join(reversed(out))


@dataclass(frozen=True, order=True)
class RunId(Ulid):
    pass


@dataclass(frozen=True, order=True)
class GateId(Ulid):
    pass


@dataclass(frozen=True, order=True)
class DecisionId(Ulid):
    pass


@dataclass(frozen=True, order=True)
class EffectId(Ulid):
    pass


@dataclass(frozen=True, order=True)
class EvidenceId(Ulid):
    pass


@dataclass(frozen=True, order=True)
class OutboxId(Ulid):
    pass
