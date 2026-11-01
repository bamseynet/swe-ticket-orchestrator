"""Step broker (D5-19): the only way agent-side code reaches the ledger and flags.

Every call carries the signed step token (``sto.agents.step_token``). The broker verifies it, then
takes team, run and step identity **from the claims**. No argument names a team or run, so a session
cannot ask for another team's rows. Refreshing a token needs the per-attempt secret that the
dispatcher delivered at invoke (``(step, attempt)`` is guessable, the secret is not).

The broker has **no signing power**: it holds a ``StepReissuer``, a narrow callback to the
dispatcher that takes a verified context and returns a token. A broker that could sign could mint
for any team.

Rules, all fail-closed:

* Reads, flags and refreshes are refused once the step is not live (ended, superseded, unknown, or
  past its deadline).
* A refresh passes the verified context unchanged, so it cannot widen stage, tools, repo or SHA. The
  new token is verified again against the broker's pinned issuer, audience and algorithm, and must
  carry the same context. The reissuer clamps the expiry to the deadline.
* Only agent-readable ledger rows can be read (``READABLE_PREFIXES``), never ``TOK#`` rows.
* The directory keeps a SHA-256 digest of each secret, compared in constant time.
* A failing dependency (store, directory, flag sink, reissuer) propagates; nothing is swallowed.

Note for later issues: "ledger" has two meanings. ``read_ledger`` covers run rows only; ``BUD#``
rows are refused. D10-03 and D11-04 settle what an agent may read of the budget.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from sto.agents.step_token import (
    StepContext,
    StepReissuer,
    StepToken,
    StepTokenError,
    StepTokenVerifier,
)
from sto.store.ports import Item, Key, Store, TeamScope

SECRET_BYTES: Final = 32
# Rows of the caller's own run that a session may read. Not STEP# (it holds other attempts' fences
# and session IDs), and never TOK#, FX#, OUT#, CHAIN or META.
READABLE_PREFIXES: Final = ("TICKET#", "EV#", "ROUTE#")
MAX_SK_LEN: Final = 200
MAX_FLAG_NAME: Final = 64
MAX_FLAG_DETAIL: Final = 2048


def new_attempt_secret() -> bytes:
    """A fresh random per-attempt secret. The dispatcher delivers it once, at invoke."""
    return secrets.token_bytes(SECRET_BYTES)


@dataclass(frozen=True)
class AttemptRecord:
    secret_digest: bytes
    deadline: int
    live: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.secret_digest, bytes) or len(self.secret_digest) != 32:
            raise StepTokenError("invalid attempt record")
        if type(self.deadline) is not int or self.deadline < 0:
            raise StepTokenError("invalid attempt record")
        if type(self.live) is not bool:
            raise StepTokenError("invalid attempt record")

    def __repr__(self) -> str:  # never show the digest
        return f"AttemptRecord(deadline={self.deadline}, live={self.live})"


@runtime_checkable
class AttemptDirectory(Protocol):
    """Which step attempts are live, with the digest of each attempt's secret.

    A *step* is ``(team, run, stage, visit)``; an *attempt* adds ``attempt``. Rules every
    implementation must keep:

    * Registering attempt N **supersedes** every lower attempt of the same step. Their ``attempt()``
      reports ``live=False`` from then on, so attempt 1 cannot refresh or read once 2 is registered.
    * Registering a lower attempt than one already registered, an attempt that has ended, or an
      attempt that is already registered, is refused. An ended attempt is never revived.
    * ``end()`` is permanent and also works **before** ``register()``: a cancel that arrives first
      sticks, and the later ``register()`` is refused.
    * ``deadline`` is an ``int`` (epoch seconds); anything else is refused.
    """

    def attempt(self, context: StepContext) -> AttemptRecord | None:
        """The record, with ``live`` False once ended or superseded, or ``None`` if unknown."""
        ...


class InMemoryAttemptDirectory:
    """For tests and a single host. The engine's step store replaces it in a deployment."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str, int, int], AttemptRecord] = {}
        self._latest: dict[tuple[str, str, str, int], int] = {}
        self._ended: set[tuple[str, str, str, int, int]] = set()

    @staticmethod
    def _step(c: StepContext) -> tuple[str, str, str, int]:
        return (c.team, c.run, c.stage, c.visit)

    @classmethod
    def _key(cls, c: StepContext) -> tuple[str, str, str, int, int]:
        return (*cls._step(c), c.attempt)

    def register(self, context: StepContext, secret: bytes, *, deadline: int) -> None:
        if not isinstance(secret, bytes) or len(secret) < SECRET_BYTES:
            raise StepTokenError("invalid attempt secret")
        record = AttemptRecord(secret_digest=hashlib.sha256(secret).digest(), deadline=deadline)
        key = self._key(context)
        if key in self._ended:
            raise StepTokenError("attempt ended")
        if key in self._records:
            raise StepTokenError("attempt already registered")
        if context.attempt <= self._latest.get(self._step(context), 0):
            raise StepTokenError("attempt superseded")
        self._records[key] = record
        self._latest[self._step(context)] = context.attempt

    def end(self, context: StepContext) -> None:
        self._ended.add(self._key(context))

    def attempt(self, context: StepContext) -> AttemptRecord | None:
        key = self._key(context)
        record = self._records.get(key)
        if record is None:
            return None
        current = self._latest[self._step(context)] == context.attempt
        if key in self._ended or not current:
            return AttemptRecord(record.secret_digest, record.deadline, live=False)
        return record


class FlagSink(Protocol):
    def raise_flag(self, context: StepContext, name: str, detail: str) -> None: ...


class StepBroker:
    def __init__(
        self,
        *,
        verifier: StepTokenVerifier,
        reissuer: StepReissuer,
        directory: AttemptDirectory,
        store: Store,
        flags: FlagSink,
    ) -> None:
        if type(reissuer.ttl) is not int or not 0 < reissuer.ttl <= verifier.max_ttl:
            raise StepTokenError("reissuer ttl must be positive and within the verifier's max_ttl")
        self._verifier = verifier
        self._reissuer = reissuer
        self._directory = directory
        self._store = store
        self._flags = flags

    def _live(self, token: str, now: int) -> tuple[StepToken, AttemptRecord]:
        verified = self._verifier.verify(token, now=now)
        record = self._directory.attempt(verified.context)
        if record is None or not record.live:
            raise StepTokenError("step not live")
        if now >= record.deadline:
            raise StepTokenError("step deadline passed")
        return verified, record

    def read_ledger(self, token: str, sk: str, *, now: int) -> Item | None:
        """Read one row of this step's own run, in this step's own team."""
        verified, _ = self._live(token, now)
        if (
            not isinstance(sk, str)
            or len(sk) > MAX_SK_LEN
            or not sk.isprintable()
            or not sk.startswith(READABLE_PREFIXES)
        ):
            raise StepTokenError("ledger row not readable")
        c = verified.context
        return self._store.get(TeamScope(c.team), Key(f"RUN#{c.run}", sk))

    def raise_flag(self, token: str, name: str, detail: str, *, now: int) -> None:
        verified, _ = self._live(token, now)
        if (
            not isinstance(name, str)
            or not isinstance(detail, str)
            or not name
            or len(name) > MAX_FLAG_NAME
            or not name.isprintable()
            or len(detail) > MAX_FLAG_DETAIL
        ):
            raise StepTokenError("invalid flag")
        self._flags.raise_flag(verified.context, name, detail)

    def refresh(self, token: str, secret: bytes, *, now: int) -> str:
        """Ask the dispatcher for a new token with the same context, if the step is live."""
        verified, record = self._live(token, now)
        if not isinstance(secret, bytes) or not hmac.compare_digest(
            hashlib.sha256(secret).digest(), record.secret_digest
        ):
            raise StepTokenError("bad attempt secret")
        new = self._reissuer.reissue(verified.context, now=now)
        # The reissuer is outside this process in a deployment: trust nothing it returns.
        again = self._verifier.verify(new, now=now)
        if again.context != verified.context:
            raise StepTokenError("reissued token changed the context")
        if again.exp > record.deadline:
            raise StepTokenError("reissued token outlives the step")
        return new
