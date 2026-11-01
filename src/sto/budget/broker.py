"""Step broker (D5-19): the only way agent-side code reaches the ledger and flags.

Every call carries the signed step token (``sto.agents.step_token``). The broker verifies it, then
takes team, run and step identity **from the claims**. No argument names a team or run, so a session
cannot ask for another team's rows. Refreshing a token needs the per-attempt secret that the
dispatcher delivered at invoke (``(step, attempt)`` is guessable, the secret is not).

The broker has **no signing power**: it holds a ``StepReissuer``, a narrow callback to the
dispatcher that takes the presented token and the attempt secret and returns a token. The
dispatcher re-checks both, so a compromised broker cannot mint for any other team, stage or scope.

Rules, all fail-closed:

* Reads, flags and refreshes are refused once the step is not live (ended, superseded, unknown, or
  past its deadline).
* The broker checks the token, liveness and secret before it calls the reissuer (defence in depth),
  and verifies what comes back: pinned issuer, audience and algorithm, the same context, the step
  still live, and an expiry within the deadline.
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
import threading
from typing import Final, Protocol

from sto.agents.step_token import (
    AttemptDirectory,
    AttemptRecord,
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


class InMemoryAttemptDirectory:
    """For tests and a single host. The engine's step store replaces it in a deployment."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
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
        record = AttemptRecord(
            context=context, secret_digest=hashlib.sha256(secret).digest(), deadline=deadline
        )
        key = self._key(context)
        with self._lock:
            if key in self._ended:
                raise StepTokenError("attempt ended")
            if key in self._records:
                raise StepTokenError("attempt already registered")
            if context.attempt <= self._latest.get(self._step(context), 0):
                raise StepTokenError("attempt superseded")
            self._records[key] = record
            self._latest[self._step(context)] = context.attempt

    def end(self, context: StepContext) -> None:
        with self._lock:
            self._ended.add(self._key(context))
            step = self._step(context)
            self._latest[step] = max(self._latest.get(step, 0), context.attempt)

    def attempt(self, context: StepContext) -> AttemptRecord | None:
        key = self._key(context)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                return None
            if key in self._ended or self._latest[self._step(context)] != context.attempt:
                return AttemptRecord(
                    record.context, record.secret_digest, record.deadline, live=False
                )
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
        new = self._reissuer.reissue(token, secret, now=now)
        # The reissuer is outside this process in a deployment: trust nothing it returns.
        again, again_record = self._live(new, now)
        if again.context != verified.context:
            raise StepTokenError("reissued token changed the context")
        if again.exp > again_record.deadline:
            raise StepTokenError("reissued token outlives the step")
        return new
