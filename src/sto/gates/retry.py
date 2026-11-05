"""Retry pacing for gate writes (D3-17).

Every decision of a run serialises on the audit chain head, so N concurrent approvals of a gate
whose quorum is N all conflict with each other: each commit moves the head under the other N-1.
Retrying at once, in lock step, loses the same race again; 59 of 250 decisions on memory and 76 of
250 on SQLite ran out of attempts at quorum 50 (D3-06 pass-2 review). Waiting a random time
between attempts spreads the retries out so that some attempt in each round commits.

``Backoff`` is "full jitter": attempt ``n`` sleeps a uniform random time in
``[0, min(cap, base * 2**n)]``. It reads no clock and no global RNG: the sleep and the RNG are
fields, so a test passes a recording sleep and a seeded RNG and the schedule is exact. The
service owns the retry loop (every write stays behind the store port); this module only paces it.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

_MAX_DOUBLINGS = 30  # 2**30 * base is far past any cap; stops the shift growing without bound


@dataclass(frozen=True)
class Backoff:
    """How many times a gate write is tried and how long to wait between tries (seconds)."""

    base: float = 0.002
    cap: float = 0.1
    attempts: int = 100
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)
    rng: Callable[[], float] = field(default=random.random, repr=False)

    def __post_init__(self) -> None:
        if self.base <= 0:
            raise ValueError("base must be positive")
        if self.cap < self.base:
            raise ValueError("cap must not be below base")
        if self.attempts < 1:
            raise ValueError("attempts must be at least 1")

    def delay(self, attempt: int) -> float:
        """The wait after failed attempt ``attempt`` (0-based): jitter times a capped doubling."""
        ceiling = min(self.cap, self.base * (1 << min(max(attempt, 0), _MAX_DOUBLINGS)))
        return self.rng() * ceiling

    def wait(self, attempt: int) -> None:
        """Sleep after failed attempt ``attempt``; not after the last one, which has no next try."""
        if attempt + 1 < self.attempts:
            self.sleep(self.delay(attempt))
