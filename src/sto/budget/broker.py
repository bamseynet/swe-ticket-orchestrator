"""Step broker (D5-19): the only way agent-side code reaches the ledger and flags.

Every call carries the signed step token (``sto.agents.step_token``). The broker verifies it, then
takes team, run and step identity **from the claims**. No argument names a team or run, so a session
cannot ask for another team's rows. Refreshing a token needs the per-attempt secret that the
dispatcher delivered at invoke (``(step, attempt)`` is guessable, the secret is not).

Rules, all fail-closed:

* Reads, flags and refreshes are refused once the step is not live (ended, unknown or
  past its deadline).
* A refresh copies the old token's context unchanged. It takes no claims, so it cannot widen
  stage, tools, repo or SHA. The new expiry never passes the step's deadline.
* Only agent-readable ledger rows can be read (``READABLE_PREFIXES``), never ``TOK#`` rows.
* The directory keeps a SHA-256 digest of each secret, compared in constant time.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from sto.agents.step_token import (
    DEFAULT_TTL,
    StepContext,
    StepToken,
    StepTokenError,
    StepTokenVerifier,
    mint_step_token,
)
from sto.signing.port import Signer
from sto.store.ports import Item, Key, Store, TeamScope

SECRET_BYTES: Final = 32
READABLE_PREFIXES: Final = ("TICKET#", "EV#", "ROUTE#", "STEP#")
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

    def __repr__(self) -> str:
        return f"AttemptRecord(deadline={self.deadline}, live={self.live})"


@runtime_checkable
class AttemptDirectory(Protocol):
    """Which step attempts are live, with the digest of each attempt's secret."""

    def attempt(self, context: StepContext) -> AttemptRecord | None: ...


class InMemoryAttemptDirectory:
    """For tests and a single host. The engine's step store replaces it in a deployment."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str, int, int], AttemptRecord] = {}

    @staticmethod
    def _key(c: StepContext) -> tuple[str, str, str, int, int]:
        return (c.team, c.run, c.stage, c.visit, c.attempt)

    def register(self, context: StepContext, secret: bytes, *, deadline: int) -> None:
        if not isinstance(secret, bytes) or len(secret) < SECRET_BYTES:
            raise StepTokenError("invalid attempt secret")
        self._records[self._key(context)] = AttemptRecord(
            secret_digest=hashlib.sha256(secret).digest(), deadline=deadline
        )

    def end(self, context: StepContext) -> None:
        record = self._records.get(self._key(context))
        if record is not None:
            self._records[self._key(context)] = AttemptRecord(
                secret_digest=record.secret_digest, deadline=record.deadline, live=False
            )

    def attempt(self, context: StepContext) -> AttemptRecord | None:
        return self._records.get(self._key(context))


class FlagSink(Protocol):
    def raise_flag(self, context: StepContext, name: str, detail: str) -> None: ...


class StepBroker:
    def __init__(
        self,
        *,
        signer: Signer,
        verifier: StepTokenVerifier,
        directory: AttemptDirectory,
        store: Store,
        flags: FlagSink,
        ttl: int = DEFAULT_TTL,
    ) -> None:
        self._signer = signer
        self._verifier = verifier
        self._directory = directory
        self._store = store
        self._flags = flags
        self._ttl = ttl

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
        """Mint a new token with the same context, if the step is live and the secret is right."""
        verified, record = self._live(token, now)
        if not isinstance(secret, bytes) or not hmac.compare_digest(
            hashlib.sha256(secret).digest(), record.secret_digest
        ):
            raise StepTokenError("bad attempt secret")
        ttl = min(self._ttl, record.deadline - now)
        return mint_step_token(self._signer, verified.context, now=now, ttl=ttl)
