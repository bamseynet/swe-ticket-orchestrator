"""Export by team, run or period, and the verifier for it (PLAN 4.9).

An export carries entries and the signed checkpoints it was given. **A file cannot vouch for its
own completeness**: whoever edits the entries can also drop the newest checkpoint or the runs it
names. So ``verify_export`` takes the trust from the caller: checkpoints fetched from the locked
bucket (``trusted``), or at least the time of the newest checkpoint the caller expects
(``min_checkpoint_at``). A run that no checkpoint names is refused.

What is checked is chosen by the caller, not by the file:

* ``from_start``: every run starts at entry 1 (no anchor). Period exports verify with
  ``from_start=False``; their first entry hangs on an anchor that is compared with a checkpoint
  whenever one covers its seq.
* ``to_tip``: every run reaches the count of each checkpoint that names it.
* ``all_runs``: every run any checkpoint names is in the file.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sto.audit.checkpoint import SignedCheckpoint
from sto.audit.errors import AuditVerificationError
from sto.audit.port import StoreAuditLog
from sto.audit.verify import (
    check_against_checkpoints,
    check_checkpoints,
    check_entries,
    team_of,
)
from sto.domain import RunId
from sto.domain.errors import InvalidIdError
from sto.gates.hooks import GENESIS_HASH
from sto.signing.port import Verifier
from sto.store.ports import Scope, Store

FORMAT = "sto.audit.export.v1"


def _window(entries: list[dict[str, Any]], since: int | None, until: int | None) -> slice:
    """The one contiguous stretch from the first entry at or after ``since`` to the last one
    before ``until``. Clocks skew, so ``at`` is not monotonic and a filter would leave holes."""
    idx = range(len(entries))
    start = next((i for i in idx if since is None or entries[i]["at"] >= since), None)
    end = next((i for i in reversed(idx) if until is None or entries[i]["at"] < until), None)
    if start is None or end is None or start > end:
        return slice(0, 0)
    return slice(start, end + 1)


def export_team(
    store: Store,
    scope: Scope,
    run_ids: Iterable[RunId],
    *,
    checkpoints: Sequence[SignedCheckpoint] = (),
    since: int | None = None,
    until: int | None = None,
) -> dict[str, Any]:
    """A JSON-able document of the runs given and every run a checkpoint names."""
    log = StoreAuditLog(store)
    names = {str(r) for r in run_ids} | {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    runs: dict[str, Any] = {}
    for run in sorted(names):
        entries = [dict(e) for e in log.entries(scope, RunId.parse(run))]
        picked = entries[_window(entries, since, until)]
        anchor = None
        if picked and picked[0]["seq"] > 1:
            before = entries[picked[0]["seq"] - 2]
            anchor = {"seq": before["seq"], "hash": before["hash"]}
        runs[run] = {"entries": picked, "anchor": anchor}
    return {
        "format": FORMAT,
        "team": team_of(scope),
        "window": {"since": since, "until": until},
        "runs": runs,
        "checkpoints": [c.to_wire() for c in checkpoints],
    }


def export_json(*args: Any, **kwargs: Any) -> str:
    return json.dumps(export_team(*args, **kwargs), sort_keys=True, indent=2)


def verify_export(
    doc: Mapping[str, Any],
    verifier: Verifier,
    *,
    trusted: Sequence[SignedCheckpoint] = (),
    min_checkpoint_at: int | None = None,
    from_start: bool = True,
    to_tip: bool = True,
    all_runs: bool = True,
) -> dict[str, int]:
    """Check an export. Returns entries per run; raises ``AuditVerificationError`` (also for a
    malformed file). The caller must give ``trusted`` checkpoints or ``min_checkpoint_at``."""
    try:
        return _verify_export(
            doc, verifier, trusted, min_checkpoint_at, from_start, to_tip, all_runs
        )
    except AuditVerificationError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, InvalidIdError) as exc:
        raise AuditVerificationError("malformed export") from exc


def _verify_export(
    doc: Mapping[str, Any],
    verifier: Verifier,
    trusted: Sequence[SignedCheckpoint],
    min_checkpoint_at: int | None,
    from_start: bool,
    to_tip: bool,
    all_runs: bool,
) -> dict[str, int]:
    if doc.get("format") != FORMAT:
        raise AuditVerificationError("not an audit export")
    team = doc["team"]
    if not isinstance(team, str):
        raise AuditVerificationError("malformed export")
    if not trusted and min_checkpoint_at is None:
        raise AuditVerificationError(
            "the caller must give trusted checkpoints or a minimum checkpoint time"
        )
    checkpoints = [*(SignedCheckpoint.from_wire(w) for w in doc["checkpoints"]), *trusted]
    if not checkpoints:
        raise AuditVerificationError("no checkpoint to verify the export against")
    check_checkpoints(team, checkpoints, verifier)
    newest = max(c.checkpoint.at for c in checkpoints)
    if min_checkpoint_at is not None and newest < min_checkpoint_at:
        raise AuditVerificationError("the newest checkpoint is older than the caller requires")
    named = {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    runs = doc["runs"]
    if not isinstance(runs, Mapping):
        raise AuditVerificationError("malformed export")
    parsed = {str(RunId.parse(k)): v for k, v in runs.items()}  # a bad key never reaches a message
    if len(parsed) != len(runs):
        raise AuditVerificationError("malformed export")
    if parsed.keys() - named:
        raise AuditVerificationError("the export holds a run that no checkpoint names")
    if all_runs and named - parsed.keys():
        raise AuditVerificationError(f"run {sorted(named - parsed.keys())[0]} is not in the export")
    counts: dict[str, int] = {}
    for run, body in parsed.items():
        entries, anchor = body["entries"], body.get("anchor")
        if anchor is None:
            start, hashes = (0, GENESIS_HASH), {}
        else:
            a_seq, a_hash = anchor["seq"], anchor["hash"]
            if type(a_seq) is not int or a_seq < 1 or not isinstance(a_hash, str):
                raise AuditVerificationError("malformed export")
            start, hashes = (a_seq, a_hash), {a_seq: a_hash}
            if from_start:
                raise AuditVerificationError(f"run {run} does not start at the beginning")
        walked = check_entries(entries, run, team, anchor=start)
        hashes.update(walked)
        counts[run] = len(entries)
        check_against_checkpoints(
            run,
            hashes,
            first=start[0] + 1,
            last=start[0] + len(entries),
            to_tip=to_tip,
            checkpoints=checkpoints,
        )
    return counts
