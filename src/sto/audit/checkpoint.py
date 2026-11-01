"""Signed checkpoints (PLAN 4.9): per team, over each run's entry count and head hash.

A chain is unkeyed, so someone with write access can edit and re-hash it, or cut off a tail or a
whole run, and the chain still agrees with itself. A checkpoint is signed through the signer
port (its own key, see ``sto.signing.port``) and kept outside the table (the locked bucket), so
the verifier can compare the table against it.

Limit, by design: a checkpoint proves what existed when it was signed. Anything done past the
newest checkpoint is not covered by it: entries removed down to a count it already covers, and
entries edited and re-hashed after its count, both pass. A run begun after the newest checkpoint
is not named by it. Protection of those starts when the entry reaches the locked bucket.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sto.audit.errors import AuditVerificationError
from sto.domain import RunId
from sto.domain.errors import InvalidIdError
from sto.signing.port import Signature, Signer, SigningError, Verifier
from sto.store.ports import Scope, Store, TeamScope

DOMAIN = b"sto.audit.checkpoint.v1\n"


@dataclass(frozen=True)
class RunHead:
    run_id: str
    count: int
    hash: str


@dataclass(frozen=True)
class Checkpoint:
    team: str
    at: int
    runs: tuple[RunHead, ...]

    def to_wire(self) -> dict[str, Any]:
        return {
            "team": self.team,
            "at": self.at,
            "runs": [{"run": h.run_id, "count": h.count, "hash": h.hash} for h in self.runs],
        }

    def payload(self) -> bytes:
        blob = json.dumps(self.to_wire(), sort_keys=True, separators=(",", ":"))
        return DOMAIN + blob.encode()


@dataclass(frozen=True)
class SignedCheckpoint:
    checkpoint: Checkpoint
    signature: str

    def is_signed_by(self, verifier: Verifier) -> bool:
        try:
            return verifier.verify(self.checkpoint.payload(), Signature.decode(self.signature))
        except SigningError:
            return False

    def to_wire(self) -> dict[str, Any]:
        return {**self.checkpoint.to_wire(), "signature": self.signature}

    @classmethod
    def from_wire(cls, wire: Mapping[str, Any]) -> SignedCheckpoint:
        try:
            runs = tuple(
                RunHead(str(RunId.parse(r["run"])), _count(r["count"]), _text(r["hash"]))
                for r in wire["runs"]
            )
            at, team = wire["at"], wire["team"]
            if type(at) is not int or not isinstance(team, str):
                raise TypeError("at/team")
            return cls(Checkpoint(team, at, runs), _text(wire["signature"]))
        except (KeyError, TypeError, ValueError, AttributeError, InvalidIdError) as exc:
            raise AuditVerificationError("malformed checkpoint") from exc


def _count(value: object) -> int:
    if type(value) is not int or value < 1:
        raise TypeError("count")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("text")
    return value


def create_checkpoint(
    store: Store,
    scope: Scope,
    signer: Signer,
    run_ids: Iterable[RunId],
    *,
    at: int,
    previous: Sequence[SignedCheckpoint],
) -> SignedCheckpoint:
    """Sign the current head of every run in ``run_ids`` and of every run an earlier checkpoint
    named. ``previous`` is required (pass ``[]`` for the first one): the store is first verified
    against it, so a checkpoint is never signed over a table that already lost data."""
    from sto.audit.verify import verify_team, walk_run

    if not isinstance(scope, TeamScope):
        raise ValueError("checkpoints are per team")
    ids = {str(r) for r in run_ids} | {h.run_id for cp in previous for h in cp.checkpoint.runs}
    verify_team(
        store,
        scope,
        [RunId.parse(i) for i in ids],
        checkpoints=previous,
        verifier=signer,
        allow_unanchored=True,  # the first checkpoint has nothing to be anchored to
        allow_uncovered=True,  # new runs are what this checkpoint is for
    )
    heads = []
    for run in sorted(ids):
        count, last = walk_run(store, scope, RunId.parse(run))
        if count:
            heads.append(RunHead(run, count, last))
    cp = Checkpoint(scope.team, at, tuple(heads))
    return SignedCheckpoint(cp, signer.sign(cp.payload()).encode())
